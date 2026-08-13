/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_lab_provisioner.h"

#include "in_memory_storage.h"
#include "n6_crypto_provider.h"
#include "pcp_lab_session_ledger.h"
#include "r7_crypto_openssl3.h"
#include "v1_lab_binding.h"

#include "ninlil/fabric_v1.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(x)                                                           \
    do {                                                                     \
        if (!(x)) {                                                          \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static const uint8_t k_lab_namespace[] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'v', '1', '.', 'l', 'a', 'b'};
static const uint8_t k_n6_namespace[] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'n', '6', '.', 'v', '1'};

typedef struct test_n6 {
    uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    uint8_t pool_bytes[4096u];
    ninlil_n6_t *n6;
} test_n6_t;

static ninlil_pcp_lab_session_ledger_t g_session_ledger;

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void fill_endpoint(ninlil_v1_lab_endpoint_t *endpoint, uint8_t seed)
{
    (void)memset(endpoint, 0, sizeof(*endpoint));
    fill_bytes(endpoint->runtime_id, 16u, seed);
    fill_bytes(endpoint->application_id, 16u, (uint8_t)(seed + 0x10u));
    fill_bytes(endpoint->device_id, 16u, (uint8_t)(seed + 0x20u));
    fill_bytes(endpoint->site_id, 16u, 0x70u);
    endpoint->binding_epoch = 1u;
    endpoint->membership_epoch = 1u;
    endpoint->identity_flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    fill_bytes(endpoint->clock_epoch_id, 16u, seed);
    endpoint->clock_trust = NINLIL_CLOCK_TRUSTED;
}

static void fill_binding(
    ninlil_v1_lab_binding_t *binding,
    uint8_t peer_seed,
    uint64_t pair_generation,
    uint64_t membership_epoch,
    uint32_t context_id,
    uint8_t secret_seed)
{
    ninlil_v1_lab_service_row_t *row;

    (void)memset(binding, 0, sizeof(*binding));
    binding->service_count = 1u;
    binding->pair_generation = pair_generation;
    fill_endpoint(&binding->endpoint_a, 0x10u);
    fill_endpoint(&binding->endpoint_b, peer_seed);
    fill_bytes(binding->radio_site_domain_id, 16u, 0x90u);
    binding->radio_membership_epoch = membership_epoch;
    binding->a_to_b_hop_context_id = context_id;
    binding->a_to_b_e2e_context_id = context_id;
    binding->b_to_a_hop_context_id = context_id;
    binding->b_to_a_e2e_context_id = context_id;
    fill_bytes(binding->a_to_b_hop_secret, 32u, secret_seed);
    fill_bytes(binding->a_to_b_e2e_secret, 32u,
        (uint8_t)(secret_seed + 0x20u));
    fill_bytes(binding->b_to_a_hop_secret, 32u,
        (uint8_t)(secret_seed + 0x40u));
    fill_bytes(binding->b_to_a_e2e_secret, 32u,
        (uint8_t)(secret_seed + 0x60u));
    row = &binding->services[0];
    row->slot = 1u;
    row->flow = NINLIL_V1_LAB_FLOW_A_TO_B;
    row->namespace_length = 3u;
    row->service_length = 3u;
    row->schema_length = 3u;
    row->descriptor_revision = 1u;
    fill_bytes(row->descriptor_digest, 32u, peer_seed);
    row->schema_major = 1u;
    row->schema_minor = 0u;
    row->family = NINLIL_FAMILY_DESIRED_STATE;
    row->direction = NINLIL_DIRECTION_DOWNLINK;
    row->traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    row->evidence_grace_ms = 1000u;
    (void)memcpy(row->namespace_id, "lab", 3u);
    (void)memcpy(row->service_id, "svc", 3u);
    (void)memcpy(row->schema_id, "bin", 3u);
}

static void fill_class_d(
    ninlil_r2_authority_clock_result_t *sample,
    const uint8_t epoch_id[16])
{
    (void)memset(sample, 0, sizeof(*sample));
    sample->typed_class = NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH;
    sample->sample_fields_valid = 1u;
    sample->sample_trust = NINLIL_CLOCK_TRUSTED;
    sample->result_catalog = NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP;
    sample->exact_status = NINLIL_PCP_OK;
    sample->business_mutation = NINLIL_R2_SAMPLE_BUSINESS_ZERO;
    sample->durable_meta_mutation = NINLIL_R2_SAMPLE_META_ZERO;
    sample->txn_provenance = NINLIL_R2_SAMPLE_PRECHECK_ZERO;
    (void)memcpy(sample->sample_epoch_id, epoch_id, 16u);
    sample->sample_now_ms = 1000u;
}

static int init_n6(test_n6_t *test)
{
    ninlil_n6_context_pool_t pool;

    (void)memset(test, 0, sizeof(*test));
    (void)memset(&pool, 0, sizeof(pool));
    pool.max_slots = 8u;
    pool.bytes = test->pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    return pool.bytes_size <= sizeof(test->pool_bytes)
        && ninlil_n6_init(
               test->object, sizeof(test->object), &pool, &test->n6)
            == NINLIL_N6_OK
        ? 0
        : 1;
}

static int put_full(
    const ninlil_storage_ops_t *ops,
    const uint8_t *namespace_bytes,
    uint32_t namespace_length,
    const uint8_t *key_bytes,
    uint32_t key_length,
    const uint8_t *value_bytes,
    uint32_t value_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_bytes_view_t storage_namespace = {
        namespace_bytes, namespace_length};
    ninlil_bytes_view_t key = {key_bytes, key_length};
    ninlil_bytes_view_t value = {value_bytes, value_length};

    if (ops->open(ops->user, storage_namespace, 1u, &handle)
            != NINLIL_STORAGE_OK
        || handle == NULL
        || ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            != NINLIL_STORAGE_OK
        || txn == NULL
        || ops->put(ops->user, txn, key, value) != NINLIL_STORAGE_OK
        || ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        if (txn != NULL) {
            (void)ops->rollback(ops->user, txn);
        }
        if (handle != NULL) {
            ops->close(ops->user, handle);
        }
        return 1;
    }
    ops->close(ops->user, handle);
    return 0;
}

static uint32_t count_namespace(
    const ninlil_storage_ops_t *ops,
    const uint8_t *namespace_bytes,
    uint32_t namespace_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_bytes_view_t storage_namespace = {
        namespace_bytes, namespace_length};
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint8_t key_bytes[64];
    uint8_t value_bytes[1024];
    uint32_t count = 0u;

    if (ops->open(ops->user, storage_namespace, 1u, &handle)
            != NINLIL_STORAGE_OK
        || handle == NULL
        || ops->begin(ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
            != NINLIL_STORAGE_OK
        || txn == NULL
        || ops->iter_open(ops->user, txn, prefix, &iter)
            != NINLIL_STORAGE_OK
        || iter == NULL) {
        return UINT32_MAX;
    }
    for (;;) {
        ninlil_mut_bytes_t key = {
            key_bytes, (uint32_t)sizeof(key_bytes), 0u};
        ninlil_mut_bytes_t value = {
            value_bytes, (uint32_t)sizeof(value_bytes), 0u};
        ninlil_storage_status_t status =
            ops->iter_next(ops->user, iter, &key, &value);
        if (status == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (status != NINLIL_STORAGE_OK) {
            count = UINT32_MAX;
            break;
        }
        count += 1u;
    }
    ops->iter_close(ops->user, iter);
    (void)ops->rollback(ops->user, txn);
    ops->close(ops->user, handle);
    return count;
}

static int seed_binding(
    const ninlil_storage_ops_t *ops,
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding)
{
    uint8_t key[36];

    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, binding)
        == NINLIL_V1_LAB_BINDING_OK);
    (void)memcpy(key, "NLB1", 4u);
    (void)memcpy(key + 4u, binding->pair_id, 32u);
    REQUIRE(put_full(ops, k_lab_namespace,
                (uint32_t)sizeof(k_lab_namespace), key, sizeof(key),
                binding->raw, (uint32_t)binding->raw_length)
        == 0);
    return 0;
}

static int test_two_pairs_and_restart(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t first_n6;
    test_n6_t second_n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t first;
    ninlil_v1_lab_binding_t second;
    ninlil_v1_lab_binding_t renewed;
    ninlil_v1_lab_binding_t max_generation;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_v1_lab_provision_status_t install_status;
    uint32_t n6_row_count;
    ninlil_r2_authority_clock_result_t sample;
    uint8_t stale_key[2] = {'O', 0u};
    static const uint8_t stale_value[] = {1u};
    uint8_t stale_index;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    for (stale_index = 0u; stale_index < 32u; ++stale_index) {
        stale_key[1] = stale_index;
        REQUIRE(put_full(ops, k_n6_namespace,
                    (uint32_t)sizeof(k_n6_namespace), stale_key,
                    sizeof(stale_key), stale_value, sizeof(stale_value))
            == 0);
    }
    fill_binding(&first, 0x30u, 1u, 10u, 1u, 0x11u);
    fill_binding(&second, 0x50u, 2u, 10u, 2u, 0x31u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &first)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &second)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, first.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&first_n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, first_n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                first.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ninlil_n6_state(first_n6.n6) == NINLIL_N6_STATE_INIT);
    fill_binding(&max_generation, 0x30u, UINT32_MAX, 10u, 1u, 0x11u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &max_generation)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                max_generation.raw, max_generation.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    REQUIRE(ninlil_n6_state(first_n6.n6) == NINLIL_N6_STATE_INIT);
    REQUIRE(count_namespace(ops, k_n6_namespace,
                (uint32_t)sizeof(k_n6_namespace))
        == 32u);
    ninlil_v1_lab_binding_clear(&max_generation);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                first.raw, first.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(handles.a_to_b_hop != 0u && handles.b_to_a_e2e != 0u);
    install_status = ninlil_v1_lab_provisioner_install_pair(&provisioner,
        second.raw, second.raw_length, &handles);
    if (install_status != NINLIL_V1_LAB_PROVISION_OK) {
        ninlil_n6_error_t error;
        (void)memset(&error, 0, sizeof(error));
        (void)ninlil_n6_last_error(first_n6.n6, &error);
        (void)fprintf(stderr, "second install=%u n6=%u fenced=%d\n",
            (unsigned)install_status, (unsigned)provisioner.last_n6_status,
            ninlil_v1_lab_provisioner_is_fenced(&provisioner));
        (void)fprintf(stderr, "n6 reason=%u state=%u hint=%s\n",
            (unsigned)error.reason, (unsigned)error.state, error.hint);
    }
    REQUIRE(install_status == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.active_pair_count == 2u);
    REQUIRE(count_namespace(ops, k_lab_namespace,
                (uint32_t)sizeof(k_lab_namespace))
        == 2u);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    REQUIRE(ninlil_n6_state(first_n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    n6_row_count = count_namespace(
        ops, k_n6_namespace, (uint32_t)sizeof(k_n6_namespace));
    if (n6_row_count != 24u) {
        (void)fprintf(stderr, "two-pair N6 rows=%u\n",
            (unsigned)n6_row_count);
    }
    REQUIRE(n6_row_count == 24u);
    ninlil_test_storage_simulate_crash(storage);

    REQUIRE(init_n6(&second_n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, second_n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                first.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.floor_count == 2u);
    REQUIRE(provisioner.global_membership_floor == 10u);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                first.raw, first.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    fill_binding(&renewed, 0x30u, 2u, 10u, 1u, 0x71u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &renewed)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                renewed.raw, renewed.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    fill_binding(&renewed, 0x30u, 2u, 11u, 1u, 0x11u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &renewed)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                renewed.raw, renewed.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    fill_binding(&renewed, 0x30u, 2u, 11u, 1u, 0x71u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &renewed)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                renewed.raw, renewed.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    REQUIRE(count_namespace(ops, k_n6_namespace,
                (uint32_t)sizeof(k_n6_namespace))
        == 14u);
    ninlil_v1_lab_binding_clear(&first);
    ninlil_v1_lab_binding_clear(&second);
    ninlil_v1_lab_binding_clear(&renewed);
    ninlil_v1_lab_binding_clear(&max_generation);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_fifth_floor(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t bindings[5];
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;
    uint8_t i;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    for (i = 0u; i < 4u; ++i) {
        fill_binding(&bindings[i], (uint8_t)(0x30u + 0x10u * i),
            1u, (uint64_t)(10u + i), (uint32_t)(i + 1u),
            (uint8_t)(0x11u + 0x10u * i));
        REQUIRE(seed_binding(ops, crypto, &bindings[i]) == 0);
    }
    fill_binding(&bindings[4], 0x78u, 1u, 20u, 8u, 0x71u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &bindings[4])
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, bindings[4].endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                bindings[4].endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.floor_count == 4u);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                bindings[4].raw, bindings[4].raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_CAPACITY);
    REQUIRE(ninlil_v1_lab_provisioner_is_fenced(&provisioner) == 1);
    REQUIRE(ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    for (i = 0u; i < 5u; ++i) {
        ninlil_v1_lab_binding_clear(&bindings[i]);
    }
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_malformed_boot(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t binding;
    ninlil_r2_authority_clock_result_t sample;
    uint8_t key[36];
    uint8_t malformed[NINLIL_V1_LAB_BINDING_MIN_BYTES];

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    (void)memset(key, 0, sizeof(key));
    (void)memcpy(key, "NLB1", 4u);
    (void)memset(malformed, 0, sizeof(malformed));
    REQUIRE(put_full(ops, k_lab_namespace,
                (uint32_t)sizeof(k_lab_namespace), key, sizeof(key),
                malformed, sizeof(malformed))
        == 0);
    fill_binding(&binding, 0x30u, 1u, 10u, 1u, 0x11u);
    fill_class_d(&sample, binding.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                binding.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_CORRUPT);
    REQUIRE(ninlil_v1_lab_provisioner_is_fenced(&provisioner) == 1);
    REQUIRE(ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_n6_secure_zero(malformed, sizeof(malformed));
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_storage_failure_fences(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;
    ninlil_storage_handle_t held_lab = NULL;
    ninlil_bytes_view_t lab_namespace = {
        k_lab_namespace, (uint32_t)sizeof(k_lab_namespace)};

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    fill_binding(&binding, 0x30u, 1u, 10u, 1u, 0x11u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, binding.endpoint_a.clock_epoch_id);

    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                binding.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
                NINLIL_TEST_STORAGE_OP_COMMIT,
                NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, 0)
        == 1);
    (void)memset(&handles, 0xa5, sizeof(handles));
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                binding.raw, binding.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN);
    REQUIRE(memcmp(&handles, &(ninlil_v1_lab_n6_handles_t){0},
                sizeof(handles))
        == 0);
    REQUIRE(ninlil_v1_lab_provisioner_is_fenced(&provisioner) == 1);
    REQUIRE(ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_v1_lab_provisioner_clear(&provisioner);

    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                binding.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ops->open(ops->user, lab_namespace, 1u, &held_lab)
        == NINLIL_STORAGE_OK);
    REQUIRE(held_lab != NULL);
    (void)memset(&handles, 0xa5, sizeof(handles));
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                binding.raw, binding.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_STORAGE);
    REQUIRE(memcmp(&handles, &(ninlil_v1_lab_n6_handles_t){0},
                sizeof(handles))
        == 0);
    REQUIRE(ninlil_v1_lab_provisioner_is_fenced(&provisioner) == 1);
    REQUIRE(ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    ops->close(ops->user, held_lab);
    held_lab = NULL;
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    REQUIRE(count_namespace(ops, k_lab_namespace,
                (uint32_t)sizeof(k_lab_namespace))
        == 0u);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_publication_commit_unknown(
    const ninlil_r7_crypto_provider *crypto,
    int committed)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    fill_binding(&binding, 0x30u, 1u, 10u, 1u, 0x11u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, binding.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                binding.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);

    /* Reset plus four N6 installs commit before the NLB1 publication. */
    REQUIRE(ninlil_test_storage_fault_enqueue_after(storage,
                NINLIL_TEST_STORAGE_OP_COMMIT, 5u,
                NINLIL_STORAGE_COMMIT_UNKNOWN, 1u, 1, committed)
        == 1);
    (void)memset(&handles, 0xa5, sizeof(handles));
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                binding.raw, binding.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN);
    REQUIRE(memcmp(&handles, &(ninlil_v1_lab_n6_handles_t){0},
                sizeof(handles))
        == 0);
    REQUIRE(ninlil_v1_lab_provisioner_is_fenced(&provisioner) == 1);
    REQUIRE(ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_SHUTDOWN);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_test_storage_simulate_crash(storage);

    REQUIRE(count_namespace(ops, k_lab_namespace,
                (uint32_t)sizeof(k_lab_namespace))
        == (committed != 0 ? 1u : 0u));
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init(&provisioner, n6.n6,
                ops, ninlil_n6_crypto_host_ops(), crypto,
                binding.endpoint_a.runtime_id, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    if (committed != 0) {
        REQUIRE(provisioner.floor_count == 1u);
        REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                    binding.raw, binding.raw_length, &handles)
            == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    } else {
        REQUIRE(provisioner.floor_count == 0u);
        REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                    binding.raw, binding.raw_length, &handles)
            == NINLIL_V1_LAB_PROVISION_OK);
    }
    ninlil_v1_lab_provisioner_clear(&provisioner);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_controller_identity_adoption(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    test_n6_t restarted_n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t correct;
    ninlil_v1_lab_binding_t second;
    ninlil_v1_lab_binding_t wrong_clock;
    ninlil_v1_lab_binding_t wrong_controller;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    fill_binding(&correct, 0x30u, 1u, 10u, 1u, 0x11u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &correct)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, correct.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init_controller(&provisioner,
                n6.n6, ops, ninlil_n6_crypto_host_ops(), crypto, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.local_runtime_bound == 0u
        && provisioner.runtime_adopt_mode
            == NINLIL_V1_LAB_ADOPT_CONTROLLER);

    fill_binding(&wrong_clock, 0x30u, 1u, 10u, 1u, 0x31u);
    wrong_clock.endpoint_a.clock_epoch_id[0] ^= 0x55u;
    (void)memcpy(wrong_clock.endpoint_b.clock_epoch_id,
        wrong_clock.endpoint_a.clock_epoch_id, 16u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &wrong_clock)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                wrong_clock.raw, wrong_clock.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT);
    REQUIRE(provisioner.local_runtime_bound == 0u
        && ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_INIT);

    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                correct.raw, correct.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.local_runtime_bound == 1u
        && provisioner.local_controller_mode == 1u
        && memcmp(provisioner.local_runtime_id,
               correct.endpoint_a.runtime_id, 16u)
            == 0);

    fill_binding(&second, 0x50u, 2u, 10u, 2u, 0x51u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &second)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                second.raw, second.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.active_pair_count == 2u
        && memcmp(provisioner.local_runtime_id,
               correct.endpoint_a.runtime_id, 16u)
            == 0);

    fill_binding(&wrong_controller, 0x70u, 3u, 10u, 3u, 0x71u);
    wrong_controller.services[0].flow = NINLIL_V1_LAB_FLOW_B_TO_A;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &wrong_controller)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(wrong_controller.controller_side == NINLIL_V1_LAB_SIDE_B);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                wrong_controller.raw, wrong_controller.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT);
    REQUIRE(memcmp(provisioner.local_runtime_id,
               correct.endpoint_a.runtime_id, 16u)
        == 0);

    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_test_storage_simulate_crash(storage);
    REQUIRE(init_n6(&restarted_n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init_controller(&provisioner,
                restarted_n6.n6, ops, ninlil_n6_crypto_host_ops(), crypto,
                &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.floor_count == 2u
        && provisioner.local_runtime_bound == 0u);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                correct.raw, correct.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED);
    REQUIRE(provisioner.local_runtime_bound == 0u);
    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&correct);
    ninlil_v1_lab_binding_clear(&second);
    ninlil_v1_lab_binding_clear(&wrong_clock);
    ninlil_v1_lab_binding_clear(&wrong_controller);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_peer_identity_adoption(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t correct;
    ninlil_v1_lab_binding_t wrong_clock;
    ninlil_v1_lab_binding_t second;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    fill_binding(&correct, 0x30u, 1u, 10u, 1u, 0x11u);
    REQUIRE(memcmp(correct.endpoint_a.clock_epoch_id,
                correct.endpoint_b.clock_epoch_id, 16u)
        != 0);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &correct)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, correct.endpoint_b.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init_peer(&provisioner,
                n6.n6, ops, ninlil_n6_crypto_host_ops(), crypto, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.local_runtime_bound == 0u
        && provisioner.runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_PEER);

    wrong_clock = correct;
    wrong_clock.endpoint_b.clock_epoch_id[0] ^= 0x55u;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &wrong_clock)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                wrong_clock.raw, wrong_clock.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT);
    REQUIRE(provisioner.local_runtime_bound == 0u
        && ninlil_n6_state(n6.n6) == NINLIL_N6_STATE_INIT);

    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                correct.raw, correct.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.local_runtime_bound == 1u
        && provisioner.local_controller_mode == 0u
        && provisioner.active_pair_count == 1u
        && memcmp(provisioner.local_runtime_id,
               correct.endpoint_b.runtime_id, 16u)
            == 0);

    fill_binding(&second, 0x30u, 2u, 10u, 2u, 0x51u);
    fill_endpoint(&second.endpoint_a, 0x20u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &second)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                second.raw, second.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_CAPACITY);
    REQUIRE(provisioner.active_pair_count == 1u
        && !ninlil_v1_lab_provisioner_is_fenced(&provisioner));

    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&correct);
    ninlil_v1_lab_binding_clear(&wrong_clock);
    ninlil_v1_lab_binding_clear(&second);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_peer_identity_adoption_controller_b(
    const ninlil_r7_crypto_provider *crypto)
{
    ninlil_test_storage_config_t config = {4u, 32u, 65536u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&config);
    const ninlil_storage_ops_t *ops;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;

    REQUIRE(storage != NULL);
    ops = ninlil_test_storage_ops(storage);
    fill_binding(&binding, 0x30u, 1u, 10u, 1u, 0x11u);
    binding.services[0].flow = NINLIL_V1_LAB_FLOW_B_TO_A;
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &binding)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(binding.controller_side == NINLIL_V1_LAB_SIDE_B);
    fill_class_d(&sample, binding.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init_peer(&provisioner,
                n6.n6, ops, ninlil_n6_crypto_host_ops(), crypto, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                binding.raw, binding.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.local_runtime_bound == 1u
        && provisioner.local_controller_mode == 0u
        && memcmp(provisioner.local_runtime_id,
               binding.endpoint_a.runtime_id, 16u)
            == 0);

    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_session_ledger_v1_capacity(
    const ninlil_r7_crypto_provider *crypto)
{
    static const uint8_t pcp_namespace[] = {
        'n', 'i', 'n', 'l', 'i', 'l', '.', 'p', 'c', 'p'};
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t pcp_handle = NULL;
    ninlil_bytes_view_t pcp_name;
    test_n6_t n6;
    ninlil_v1_lab_provisioner_t provisioner;
    ninlil_v1_lab_binding_t first;
    ninlil_v1_lab_binding_t second;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_r2_authority_clock_result_t sample;

    REQUIRE(ninlil_pcp_lab_session_ledger_object_bytes()
        <= sizeof(g_session_ledger));
    REQUIRE(ninlil_pcp_lab_session_ledger_init(&g_session_ledger, &ops) == 0);
    REQUIRE(ops != NULL);
    pcp_name.data = pcp_namespace;
    pcp_name.length = (uint32_t)sizeof(pcp_namespace);
    REQUIRE(ops->open(ops->user, pcp_name, NINLIL_STORAGE_SCHEMA_M1A,
                &pcp_handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(pcp_handle != NULL);
    ops->close(ops->user, pcp_handle);

    fill_binding(&first, 0x30u, 1u, 10u, 1u, 0x11u);
    fill_binding(&second, 0x50u, 2u, 10u, 2u, 0x51u);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &first)
        == NINLIL_V1_LAB_BINDING_OK);
    REQUIRE(ninlil_v1_lab_binding_finalize(crypto, &second)
        == NINLIL_V1_LAB_BINDING_OK);
    fill_class_d(&sample, first.endpoint_a.clock_epoch_id);
    REQUIRE(init_n6(&n6) == 0);
    REQUIRE(ninlil_v1_lab_provisioner_init_controller(&provisioner,
                n6.n6, ops, ninlil_n6_crypto_host_ops(), crypto, &sample)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                first.raw, first.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(ninlil_v1_lab_provisioner_install_pair(&provisioner,
                second.raw, second.raw_length, &handles)
        == NINLIL_V1_LAB_PROVISION_OK);
    REQUIRE(provisioner.active_pair_count == 2u
        && provisioner.floor_count == 2u
        && !ninlil_v1_lab_provisioner_is_fenced(&provisioner));

    ninlil_v1_lab_provisioner_clear(&provisioner);
    ninlil_v1_lab_binding_clear(&first);
    ninlil_v1_lab_binding_clear(&second);
    ninlil_pcp_lab_session_ledger_shutdown(&g_session_ledger);
    return 0;
}

int main(void)
{
    ninlil_r7_crypto_provider crypto;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&crypto)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(test_two_pairs_and_restart(&crypto) == 0);
    REQUIRE(test_fifth_floor(&crypto) == 0);
    REQUIRE(test_malformed_boot(&crypto) == 0);
    REQUIRE(test_storage_failure_fences(&crypto) == 0);
    REQUIRE(test_publication_commit_unknown(&crypto, 0) == 0);
    REQUIRE(test_publication_commit_unknown(&crypto, 1) == 0);
    REQUIRE(test_controller_identity_adoption(&crypto) == 0);
    REQUIRE(test_peer_identity_adoption(&crypto) == 0);
    REQUIRE(test_peer_identity_adoption_controller_b(&crypto) == 0);
    REQUIRE(test_session_ledger_v1_capacity(&crypto) == 0);
    (void)fprintf(stdout, "v1_lab_provisioner_test OK\n");
    return 0;
}
