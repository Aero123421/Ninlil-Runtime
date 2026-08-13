/* SPDX-License-Identifier: Apache-2.0 */
#include "n6_context_store.h"
#include "n6_crypto_provider.h"
#include "n6_local_identity_fixture.h"
#include "n6_mem_storage.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

struct ninlil_n6_accepted_authority_token {
    uint32_t live;
    ninlil_n6_authority_accept_status_t status;
    ninlil_n6_authority_claim_t claim;
};

struct ninlil_n6_accepted_install_token {
    uint32_t live;
    ninlil_n6_install_accept_status_t status;
    ninlil_n6_install_claim_t claim;
};

typedef struct consume_counter {
    uint32_t calls;
    ninlil_n6_t *reenter_n6;
    ninlil_n6_status_t reenter_status;
} consume_counter_t;

static ninlil_n6_authority_accept_status_t consume_authority(
    void *user,
    ninlil_n6_accepted_authority_token_t *token,
    ninlil_n6_authority_claim_t *claim_out)
{
    consume_counter_t *counter = (consume_counter_t *)user;
    if (counter != NULL) {
        counter->calls += 1u;
        if (counter->reenter_n6 != NULL) {
            counter->reenter_status =
                ninlil_n6_boot_scan(counter->reenter_n6);
        }
    }
    if (token == NULL || claim_out == NULL) {
        return NINLIL_N6_AUTHORITY_ACCEPT_INTERNAL;
    }
    if (token->live == 0u) {
        return NINLIL_N6_AUTHORITY_ACCEPT_STALE;
    }
    token->live = 0u;
    if (token->status == NINLIL_N6_AUTHORITY_ACCEPT_OK) {
        *claim_out = token->claim;
    }
    return token->status;
}

static ninlil_n6_install_accept_status_t consume_install(
    void *user,
    ninlil_n6_accepted_install_token_t *token,
    ninlil_n6_install_claim_t *claim_out)
{
    consume_counter_t *counter = (consume_counter_t *)user;
    if (counter != NULL) {
        counter->calls += 1u;
        if (counter->reenter_n6 != NULL) {
            counter->reenter_status =
                ninlil_n6_boot_scan(counter->reenter_n6);
        }
    }
    if (token == NULL || claim_out == NULL) {
        return NINLIL_N6_INSTALL_ACCEPT_INTERNAL;
    }
    if (token->live == 0u) {
        return NINLIL_N6_INSTALL_ACCEPT_STALE;
    }
    token->live = 0u;
    if (token->status == NINLIL_N6_INSTALL_ACCEPT_OK) {
        *claim_out = token->claim;
    }
    return token->status;
}

static void authority_ops_init(
    ninlil_n6_authority_ops_t *ops, consume_counter_t *counter)
{
    (void)memset(ops, 0, sizeof(*ops));
    ops->abi_version = NINLIL_N6_AUTHORITY_OPS_ABI;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = counter;
    ops->consume = consume_authority;
}

static void authority_token_init(
    ninlil_n6_accepted_authority_token_t *token, uint64_t now_ms)
{
    (void)memset(token, 0, sizeof(*token));
    token->live = 1u;
    token->status = NINLIL_N6_AUTHORITY_ACCEPT_OK;
    token->claim.abi_version = NINLIL_N6_AUTHORITY_CLAIM_ABI;
    token->claim.struct_size = NINLIL_N6_AUTHORITY_CLAIM_BYTES;
    token->claim.clock_epoch_id[0] = 1u;
    token->claim.now_ms = now_ms;
}

static void install_ops_init(
    ninlil_n6_install_ops_t *ops, consume_counter_t *counter)
{
    (void)memset(ops, 0, sizeof(*ops));
    ops->abi_version = NINLIL_N6_INSTALL_OPS_ABI;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = counter;
    ops->consume = consume_install;
}

static void install_token_init(
    ninlil_n6_accepted_install_token_t *token,
    uint8_t layer,
    uint32_t context_id)
{
    (void)memset(token, 0, sizeof(*token));
    token->live = 1u;
    token->status = NINLIL_N6_INSTALL_ACCEPT_OK;
    token->claim.abi_version = NINLIL_N6_INSTALL_CLAIM_ABI;
    token->claim.struct_size = NINLIL_N6_INSTALL_CLAIM_BYTES;
    token->claim.layer_code = layer;
    token->claim.direction_code = NINLIL_N6_DIR_IR;
    token->claim.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    token->claim.context_id = context_id;
    token->claim.membership_epoch = 7u;
    token->claim.key_generation = 9u;
    (void)memset(token->claim.binding_digest32, 0x11, 32u);
    (void)memset(token->claim.traffic_secret32, 0x22, 32u);
    (void)memset(token->claim.local_node_id, 0x33, 16u);
    (void)memset(token->claim.receiver_node_id, 0x44, 16u);
}

static int test_production_accepted_path(void)
{
    static uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    static uint8_t pool_bytes[4096u];
    ninlil_n6_context_pool_t pool;
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_authority_ops_t authority_ops;
    ninlil_n6_install_ops_t install_ops;
    ninlil_n6_accepted_authority_token_t authority_token;
    ninlil_n6_accepted_install_token_t install_token;
    consume_counter_t authority_counter;
    consume_counter_t install_counter;
    ninlil_n6_handle_t handle = 0u;
    ninlil_n6_install_capsule_t raw;
    uint32_t begins;
    uint32_t puts;

    (void)memset(&authority_counter, 0, sizeof(authority_counter));
    (void)memset(&install_counter, 0, sizeof(install_counter));
    (void)memset(object, 0, sizeof(object));
    (void)memset(pool_bytes, 0, sizeof(pool_bytes));
    n6_mem_storage_reset();
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(pool.bytes_size <= sizeof(pool_bytes));
    REQUIRE(ninlil_n6_init(object, sizeof(object), &pool, &n6)
        == NINLIL_N6_OK);
    REQUIRE(n6_local_id_fixture_bind_fill(n6, 0x33u) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(n6, n6_mem_storage_ops()) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);

    authority_ops_init(&authority_ops, &authority_counter);
    authority_token_init(&authority_token, 1000u);
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(
                n6, &authority_ops, &authority_token)
        == NINLIL_N6_OK);
    REQUIRE(authority_counter.calls == 1u && authority_token.live == 0u);

    authority_token_init(&authority_token, 2000u);
    authority_token.claim.clock_epoch_id[0] = 2u;
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(
                n6, &authority_ops, &authority_token)
        == NINLIL_N6_M4_REQUIRED);
    authority_token_init(&authority_token, 999u);
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(
                n6, &authority_ops, &authority_token)
        == NINLIL_N6_M4_REQUIRED);
    authority_ops.struct_size = 1u;
    authority_token_init(&authority_token, 1001u);
    begins = authority_counter.calls;
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(
                n6, &authority_ops, &authority_token)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(authority_counter.calls == begins && authority_token.live == 1u);
    authority_ops_init(&authority_ops, &authority_counter);

    authority_token_init(&authority_token, 1001u);
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(
                n6, &authority_ops, &authority_token)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_boot_scan(n6) == NINLIL_N6_OK);

    (void)memset(&raw, 0, sizeof(raw));
    raw.provenance = NINLIL_N6_PROVENANCE_M4_AUTHENTICATED;
    raw.layer_code = NINLIL_N6_LAYER_HOP;
    raw.direction_code = NINLIL_N6_DIR_IR;
    raw.alloc_side = NINLIL_N6_ALLOC_OUTBOUND_TX;
    raw.context_id = 1u;
    raw.membership_epoch = 7u;
    raw.key_generation = 9u;
    (void)memset(raw.binding_digest32, 0x11, 32u);
    (void)memset(raw.traffic_secret32, 0x22, 32u);
    (void)memset(raw.local_node_id, 0x33, 16u);
    (void)memset(raw.receiver_node_id, 0x44, 16u);
    REQUIRE(ninlil_n6_install_hop(n6, &raw, &handle)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(handle == 0u);
    raw.provenance = NINLIL_N6_PROVENANCE_FIXTURE_ONLY;
    REQUIRE(ninlil_n6_install_hop(n6, &raw, &handle)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(handle == 0u);

    install_ops_init(&install_ops, &install_counter);
    install_token_init(&install_token, NINLIL_N6_LAYER_HOP, 1u);
    REQUIRE(ninlil_n6_install_hop_accepted(
                n6, &install_ops, &install_token, &handle)
        == NINLIL_N6_OK);
    REQUIRE(handle != 0u && install_counter.calls == 1u);
    begins = n6_mem_storage_begin_count();
    puts = n6_mem_storage_put_count();
    handle = UINT64_MAX;
    REQUIRE(ninlil_n6_install_hop_accepted(
                n6, &install_ops, &install_token, &handle)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(handle == 0u && install_counter.calls == 2u);
    REQUIRE(n6_mem_storage_begin_count() == begins);
    REQUIRE(n6_mem_storage_put_count() == puts);

    install_token_init(&install_token, NINLIL_N6_LAYER_E2E, 1u);
    REQUIRE(ninlil_n6_install_e2e_accepted(
                n6, &install_ops, &install_token, &handle)
        == NINLIL_N6_OK);
    REQUIRE(handle != 0u);

    begins = n6_mem_storage_begin_count();
    puts = n6_mem_storage_put_count();
    install_token_init(&install_token, NINLIL_N6_LAYER_HOP, 2u);
    (void)memset(install_token.claim.traffic_secret32, 0, 32u);
    REQUIRE(ninlil_n6_install_hop_accepted(
                n6, &install_ops, &install_token, &handle)
        == NINLIL_N6_M4_REQUIRED);
    REQUIRE(handle == 0u);
    REQUIRE(n6_mem_storage_begin_count() == begins);
    REQUIRE(n6_mem_storage_put_count() == puts);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int setup_ready_n6(
    uint8_t object[NINLIL_N6_OBJECT_BYTES],
    uint8_t pool_bytes[4096u],
    ninlil_n6_t **out_n6)
{
    ninlil_n6_context_pool_t pool;
    ninlil_n6_authority_ops_t ops;
    ninlil_n6_accepted_authority_token_t token;
    consume_counter_t counter;

    (void)memset(&counter, 0, sizeof(counter));
    (void)memset(object, 0, NINLIL_N6_OBJECT_BYTES);
    (void)memset(pool_bytes, 0, 4096u);
    n6_mem_storage_reset();
    pool.max_slots = 8u;
    pool.reserved_zero = 0u;
    pool.bytes = pool_bytes;
    pool.bytes_size = ninlil_n6_context_pool_bytes(pool.max_slots);
    REQUIRE(pool.bytes_size <= 4096u);
    REQUIRE(ninlil_n6_init(object, NINLIL_N6_OBJECT_BYTES, &pool, out_n6)
        == NINLIL_N6_OK);
    REQUIRE(n6_local_id_fixture_bind_fill(*out_n6, 0x33u)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_storage(*out_n6, n6_mem_storage_ops())
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_bind_crypto(*out_n6, ninlil_n6_crypto_host_ops())
        == NINLIL_N6_OK);
    authority_ops_init(&ops, &counter);
    authority_token_init(&token, 1000u);
    REQUIRE(ninlil_n6_bind_authority_stamp_accepted(*out_n6, &ops, &token)
        == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_boot_scan(*out_n6) == NINLIL_N6_OK);
    return 0;
}

static int test_claim_matrix_and_reentry(void)
{
    static uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    static uint8_t pool_bytes[4096u];
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_ops_t ops;
    ninlil_n6_accepted_install_token_t token;
    consume_counter_t counter;
    ninlil_n6_handle_t handle;
    uint32_t begins;
    uint32_t puts;

    REQUIRE(setup_ready_n6(object, pool_bytes, &n6) == 0);
    (void)memset(&counter, 0, sizeof(counter));
    install_ops_init(&ops, &counter);

    install_token_init(&token, NINLIL_N6_LAYER_E2E, 1u);
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_M4_REQUIRED);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    token.claim.alloc_side = NINLIL_N6_ALLOC_INBOUND_RX;
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_M4_REQUIRED);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    (void)memcpy(token.claim.receiver_node_id, token.claim.local_node_id, 16u);
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_M4_REQUIRED);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    token.claim.reserved_zero = 1u;
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_M4_REQUIRED);

    begins = n6_mem_storage_begin_count();
    puts = n6_mem_storage_put_count();
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    ops.struct_size = 1u;
    handle = UINT64_MAX;
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_INVALID_ARGUMENT);
    REQUIRE(handle == 0u && token.live == 1u);
    REQUIRE(n6_mem_storage_begin_count() == begins);
    REQUIRE(n6_mem_storage_put_count() == puts);

    install_ops_init(&ops, &counter);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    handle = UINT64_MAX;
    REQUIRE(ninlil_n6_install_hop_accepted(n6,
                (const ninlil_n6_install_ops_t *)(const void *)(object + 64u),
                &token, &handle)
        == NINLIL_N6_ALIAS);
    REQUIRE(handle == UINT64_MAX && token.live == 1u);

    counter.reenter_n6 = n6;
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_OK);
    REQUIRE(counter.reenter_status == NINLIL_N6_BUSY_REENTRY);
    REQUIRE(handle != 0u);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

static int test_accepted_storage_outcomes(void)
{
    static uint8_t object[NINLIL_N6_OBJECT_BYTES]
        __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
    static uint8_t pool_bytes[4096u];
    ninlil_n6_t *n6 = NULL;
    ninlil_n6_install_ops_t ops;
    ninlil_n6_accepted_install_token_t token;
    consume_counter_t counter;
    ninlil_n6_handle_t handle;

    REQUIRE(setup_ready_n6(object, pool_bytes, &n6) == 0);
    (void)memset(&counter, 0, sizeof(counter));
    install_ops_init(&ops, &counter);

    n6_mem_storage_inject_fault(N6_MEM_FAULT_PUT, 1);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_STORAGE);
    REQUIRE(handle == 0u && token.live == 0u);

    install_token_init(&token, NINLIL_N6_LAYER_HOP, 1u);
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_OK);
    REQUIRE(handle != 0u);

    n6_mem_storage_inject_cu(N6_MEM_CU_ALL_OLD);
    install_token_init(&token, NINLIL_N6_LAYER_HOP, 2u);
    token.claim.key_generation = 10u;
    REQUIRE(ninlil_n6_install_hop_accepted(n6, &ops, &token, &handle)
        == NINLIL_N6_COMMIT_UNKNOWN);
    REQUIRE(handle == 0u && token.live == 0u);
    REQUIRE(ninlil_n6_recover_cu(n6) == NINLIL_N6_OK);
    REQUIRE(ninlil_n6_shutdown(n6) == NINLIL_N6_OK);
    return 0;
}

int main(void)
{
    REQUIRE(test_production_accepted_path() == 0);
    REQUIRE(test_claim_matrix_and_reentry() == 0);
    REQUIRE(test_accepted_storage_outcomes() == 0);
    (void)fprintf(stdout, "n6_accepted_adapters_test OK\n");
    return 0;
}
