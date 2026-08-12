/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_adapter_v1.h"
#include "wifi_journal.h"
#include "wifi_sha256.h"

#include "in_memory_storage.h"

#include <ninlil/version.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(c)                                                                \
    do {                                                                        \
        if (!(c)) {                                                             \
            (void)fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);          \
            failures += 1;                                                      \
        }                                                                       \
    } while (0)

typedef struct test_exec {
    uint64_t context_id;
} test_exec_t;

typedef struct test_clock {
    uint64_t now_ms;
    uint8_t epoch[16];
    uint32_t call_count;
} test_clock_t;

static uint64_t current_context(void *user)
{
    test_exec_t *e = (test_exec_t *)user;
    return e != NULL ? e->context_id : 0u;
}

static ninlil_port_status_t clock_now(
    void *user,
    ninlil_time_sample_t *out)
{
    test_clock_t *c = (test_clock_t *)user;
    if (c == NULL || out == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    c->call_count += 1u;
    (void)memset(out, 0, sizeof(*out));
    out->abi_version = NINLIL_ABI_VERSION;
    out->struct_size = (uint16_t)sizeof(*out);
    (void)memcpy(out->clock_epoch_id.bytes, c->epoch, 16u);
    out->now_ms = c->now_ms;
    out->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static void put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64_be(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[7u - i] = (uint8_t)(v >> (8u * i));
    }
}

static void seal_config(wifi_adapter_config_v1_t *c)
{
    static const uint8_t tag[] = "NINLIL-WIFI-ADAPTER-CONFIG-V1";
    uint8_t canonical[256];
    size_t n = 0u;
#define APPEND(src_, len_)                                                      \
    do {                                                                        \
        (void)memcpy(canonical + n, (src_), (len_));                            \
        n += (len_);                                                            \
    } while (0)
    APPEND(tag, sizeof(tag) - 1u);
    put_u32_be(canonical + n, c->adapter_kind);
    n += 4u;
    put_u32_be(canonical + n, c->tls_role);
    n += 4u;
    APPEND(c->instance_id.bytes, 16u);
    put_u64_be(canonical + n, c->configuration_revision);
    n += 8u;
    (void)memset(canonical + n, 0, 32u);
    n += 32u;
    APPEND(c->local_runtime_id.bytes, 16u);
    APPEND(c->expected_peer_runtime_id.bytes, 16u);
    put_u32_be(canonical + n, c->endpoint_address_kind);
    n += 4u;
    APPEND(c->endpoint_address, 16u);
    put_u16_be(canonical + n, c->endpoint_port);
    n += 2u;
    put_u16_be(canonical + n, c->reserved_zero_u16);
    n += 2u;
    APPEND(c->network_profile_id.bytes, 16u);
    put_u64_be(canonical + n, c->network_profile_revision);
    n += 8u;
    APPEND(c->network_profile_digest, 32u);
    put_u32_be(canonical + n, c->reconnect_profile_id);
    n += 4u;
    put_u32_be(canonical + n, c->reserved_zero_u32);
    n += 4u;
    ninlil_wifi_sha256(canonical, n, c->configuration_digest);
    (void)memset(canonical, 0, sizeof(canonical));
#undef APPEND
}

static void init_config(
    wifi_adapter_config_v1_t *config,
    const ninlil_storage_ops_t *storage,
    ninlil_clock_ops_t *clock,
    ninlil_execution_ops_t *execution)
{
    (void)memset(config, 0, sizeof(*config));
    config->api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    config->struct_size = (uint16_t)sizeof(*config);
    config->adapter_kind = WIFI_ADAPTER_KIND_POSIX_TCP;
    config->tls_role = WIFI_TLS_ROLE_CLIENT;
    (void)memset(config->instance_id.bytes, 0x11, 16u);
    config->configuration_revision = 1u;
    (void)memset(config->local_runtime_id.bytes, 0x22, 16u);
    (void)memset(config->expected_peer_runtime_id.bytes, 0x33, 16u);
    config->endpoint_address_kind = WIFI_ENDPOINT_IPV4;
    config->endpoint_address[0] = 127u;
    config->endpoint_address[3] = 1u;
    config->endpoint_port = 9443u;
    config->reconnect_profile_id = WIFI_RECONNECT_PROFILE_1;
    config->storage = storage;
    config->clock = clock;
    config->execution = execution;
    seal_config(config);
}

static void *aligned_workspace(
    uint32_t bytes,
    uint32_t alignment,
    void **out_allocation)
{
    uintptr_t p;
    uint8_t *allocation;
    if (alignment == 0u || out_allocation == NULL) {
        return NULL;
    }
    allocation = (uint8_t *)malloc((size_t)bytes + alignment - 1u);
    if (allocation == NULL) {
        return NULL;
    }
    p = ((uintptr_t)allocation + alignment - 1u)
        & ~((uintptr_t)alignment - 1u);
    *out_allocation = allocation;
    return (void *)p;
}

int main(void)
{
    ninlil_test_storage_config_t storage_config;
    ninlil_test_storage_t *storage_owner;
    const ninlil_storage_ops_t *storage;
    ninlil_clock_ops_t clock_ops;
    ninlil_execution_ops_t execution_ops;
    test_clock_t clock;
    test_exec_t execution;
    wifi_adapter_config_v1_t config;
    wifi_adapter_private_v1_t *adapter = NULL;
    const ninlil_fabric_link_descriptor_v1_t *descriptor =
        (const ninlil_fabric_link_descriptor_v1_t *)(uintptr_t)1u;
    const ninlil_fabric_packet_link_ops_v1_t *link_ops = NULL;
    ninlil_fabric_packet_link_handle_t standalone_handle = NULL;
    ninlil_fabric_packet_token_t standalone_token =
        (ninlil_fabric_packet_token_t)(uintptr_t)1u;
    ninlil_fabric_packet_view_v1_t standalone_packet;
    uint8_t standalone_payload[1] = {0u};
    wifi_operational_state_v1_t operational = 99u;
    uint32_t reason = 99u;
    uint64_t epoch = 99u;
    uint32_t bytes = 99u;
    uint32_t alignment = 99u;
    uint32_t work = 99u;
    uint32_t done = 99u;
    void *allocation = NULL;
    void *workspace;
    uint8_t first_before;

    failures = 0;
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.max_namespaces = 8u;
    storage_config.max_entries_per_namespace = 32u;
    storage_config.max_bytes_per_namespace = 65536u;
    storage_owner = ninlil_test_storage_create(&storage_config);
    CHECK(storage_owner != NULL);
    storage = ninlil_test_storage_ops(storage_owner);
    CHECK(storage != NULL);

    (void)memset(&clock, 0, sizeof(clock));
    clock.now_ms = 123u;
    (void)memset(clock.epoch, 0x44, 16u);
    (void)memset(&clock_ops, 0, sizeof(clock_ops));
    clock_ops.abi_version = NINLIL_ABI_VERSION;
    clock_ops.struct_size = (uint16_t)sizeof(clock_ops);
    clock_ops.user = &clock;
    clock_ops.now = clock_now;

    execution.context_id = 7u;
    (void)memset(&execution_ops, 0, sizeof(execution_ops));
    execution_ops.abi_version = NINLIL_ABI_VERSION;
    execution_ops.struct_size = (uint16_t)sizeof(execution_ops);
    execution_ops.user = &execution;
    execution_ops.current_context_id = current_context;

    init_config(&config, storage, &clock_ops, &execution_ops);
    CHECK(wifi_workspace_required_v1(
              WIFI_ADAPTER_KIND_POSIX_TCP, &bytes, &alignment)
        == WIFI_PRIVATE_OK);
    CHECK(bytes > 0u);
    CHECK(alignment >= _Alignof(void *));
    workspace = aligned_workspace(bytes, alignment, &allocation);
    CHECK(workspace != NULL);
    if (workspace == NULL) {
        return 1;
    }

    /* Bad digest: output NULL and workspace ownership remains with caller. */
    (void)memset(workspace, 0xa5, bytes);
    first_before = ((uint8_t *)workspace)[0];
    config.configuration_digest[0] ^= 1u;
    CHECK(wifi_create_v1(&config, workspace, bytes, &adapter)
        == WIFI_PRIVATE_DENIED);
    CHECK(adapter == NULL);
    CHECK(((uint8_t *)workspace)[0] == first_before);
    config.configuration_digest[0] ^= 1u;

    CHECK(wifi_create_v1(&config, workspace, bytes, &adapter)
        == WIFI_PRIVATE_OK);
    CHECK(adapter != NULL);
    CHECK(clock.call_count == 1u);

    /* Real Attachment authority is absent: descriptor stays fail-closed. */
    CHECK(wifi_packet_link_descriptor_v1(adapter, &descriptor)
        == WIFI_PRIVATE_UNAVAILABLE);
    CHECK(descriptor == NULL);
    CHECK(wifi_packet_link_ops_v1(adapter, &link_ops) == WIFI_PRIVATE_OK);
    CHECK(link_ops != NULL);
    CHECK(link_ops->open(link_ops->user, &standalone_handle)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(standalone_handle == NULL);
    (void)memset(&standalone_packet, 0, sizeof(standalone_packet));
    standalone_packet.api_version = 1u;
    standalone_packet.struct_size =
        (uint16_t)sizeof(standalone_packet);
    standalone_packet.bytes = standalone_payload;
    standalone_packet.length = sizeof(standalone_payload);
    CHECK(link_ops->start_send(
              link_ops->user,
              (ninlil_fabric_packet_link_handle_t)(uintptr_t)1u,
              &standalone_packet,
              &standalone_token)
        == NINLIL_FABRIC_LINK_DENIED);
    CHECK(standalone_token == NULL);

    CHECK(wifi_state_v1(adapter, &operational, &reason, &epoch)
        == WIFI_PRIVATE_OK);
    CHECK(operational == WIFI_OPERATIONAL_DISABLED);
    CHECK(reason == WIFI_REASON_ATTACHMENT_AUTHORITY_UNAVAILABLE);
    CHECK(epoch == 1u);

    /* Wrong owner: all outputs zero, side effects zero. */
    execution.context_id = 8u;
    operational = 99u;
    reason = 99u;
    epoch = 99u;
    CHECK(wifi_state_v1(adapter, &operational, &reason, &epoch)
        == WIFI_PRIVATE_WRONG_THREAD);
    CHECK(operational == 0u && reason == 0u && epoch == 0u);
    execution.context_id = 7u;

    /* Destroy cannot consume an OPEN adapter. */
    CHECK(wifi_destroy_v1(adapter) == WIFI_PRIVATE_WOULD_BLOCK);
    CHECK(wifi_drain_begin_v1(adapter) == WIFI_PRIVATE_OK);
    CHECK(wifi_drain_begin_v1(adapter) == WIFI_PRIVATE_OK);
    CHECK(wifi_drain_poll_v1(adapter, &done) == WIFI_PRIVATE_OK);
    CHECK(done == 0u);
    CHECK(wifi_step_v1(adapter, 64u, &work) == WIFI_PRIVATE_OK);
    CHECK(clock.call_count == 2u);
    CHECK(work >= 1u);
    CHECK(wifi_drain_poll_v1(adapter, &done) == WIFI_PRIVATE_OK);
    CHECK(done == 1u);
    CHECK(wifi_destroy_v1(adapter) == WIFI_PRIVATE_OK);
    CHECK(((uint8_t *)workspace)[0] == 0u);
    free(allocation);

    /* Cold-restart record is never resumed as authenticated session state. */
    {
        ninlil_wifi_journal_t journal;
        ninlil_wifi_journal_attempt_t prior;
        void *allocation2 = NULL;
        void *workspace2 =
            aligned_workspace(bytes, alignment, &allocation2);
        CHECK(workspace2 != NULL);
        ninlil_wifi_journal_init(&journal);
        CHECK(ninlil_wifi_journal_open(
                  &journal, storage, storage->user, NINLIL_WIFI_JOURNAL_NS)
            == NINLIL_WIFI_OK);
        (void)memset(&prior, 0, sizeof(prior));
        prior.attempt_id = 10u;
        prior.generation = 3u;
        prior.phase = (uint8_t)NINLIL_WIFI_PHASE_ATTACHED;
        prior.write_point = 3u;
        prior.session_id[0] = 0x55u;
        CHECK(ninlil_wifi_journal_put_attempt(&journal, &prior)
            == NINLIL_WIFI_OK);
        ninlil_wifi_journal_close(&journal);

        adapter = NULL;
        CHECK(wifi_create_v1(&config, workspace2, bytes, &adapter)
            == WIFI_PRIVATE_OK);
        CHECK(clock.call_count == 3u);
        operational = 0u;
        reason = 0u;
        epoch = 0u;
        CHECK(wifi_state_v1(adapter, &operational, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        CHECK(operational == WIFI_OPERATIONAL_FENCED);
        CHECK(reason == WIFI_REASON_RECOVERED_SESSION_FENCED);
        CHECK(epoch == 2u);
        CHECK(wifi_drain_begin_v1(adapter) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(adapter, 64u, &work) == WIFI_PRIVATE_OK);
        CHECK(clock.call_count == 4u);
        CHECK(wifi_destroy_v1(adapter) == WIFI_PRIVATE_OK);
        free(allocation2);
    }

    /* Every step re-samples trusted time; regression fences before work. */
    {
        ninlil_test_storage_t *clock_storage_owner =
            ninlil_test_storage_create(&storage_config);
        const ninlil_storage_ops_t *clock_storage =
            ninlil_test_storage_ops(clock_storage_owner);
        void *allocation3 = NULL;
        void *workspace3 =
            aligned_workspace(bytes, alignment, &allocation3);
        uint32_t calls_before;
        CHECK(clock_storage_owner != NULL);
        CHECK(workspace3 != NULL);
        clock.now_ms = 500u;
        (void)memset(clock.epoch, 0x66, 16u);
        init_config(&config, clock_storage, &clock_ops, &execution_ops);
        adapter = NULL;
        CHECK(wifi_create_v1(&config, workspace3, bytes, &adapter)
            == WIFI_PRIVATE_OK);
        calls_before = clock.call_count;
        clock.now_ms = 499u;
        work = 99u;
        CHECK(wifi_step_v1(adapter, 1u, &work) == WIFI_PRIVATE_DENIED);
        CHECK(work == 0u);
        CHECK(clock.call_count == calls_before + 1u);
        CHECK(wifi_state_v1(adapter, &operational, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        CHECK(operational == WIFI_OPERATIONAL_FENCED);
        CHECK(reason == WIFI_REASON_TRUSTED_CLOCK_INVALID);
        clock.now_ms = 501u;
        CHECK(wifi_drain_begin_v1(adapter) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(adapter, 64u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_destroy_v1(adapter) == WIFI_PRIVATE_OK);
        free(allocation3);
        ninlil_test_storage_destroy(clock_storage_owner);
    }

    /*
     * Point-4 COMMIT_UNKNOWN remains adapter status 12. An epoch mismatch
     * triggers the fence; the uncertain journal handle is closed/reopened.
     */
    {
        ninlil_test_storage_t *cu_storage_owner =
            ninlil_test_storage_create(&storage_config);
        const ninlil_storage_ops_t *cu_storage =
            ninlil_test_storage_ops(cu_storage_owner);
        void *allocation4 = NULL;
        void *workspace4 =
            aligned_workspace(bytes, alignment, &allocation4);
        uint8_t original_epoch[16];
        CHECK(cu_storage_owner != NULL);
        CHECK(workspace4 != NULL);
        clock.now_ms = 1000u;
        (void)memset(clock.epoch, 0x77, 16u);
        (void)memcpy(original_epoch, clock.epoch, 16u);
        init_config(&config, cu_storage, &clock_ops, &execution_ops);
        adapter = NULL;
        CHECK(wifi_create_v1(&config, workspace4, bytes, &adapter)
            == WIFI_PRIVATE_OK);
        CHECK(ninlil_test_storage_fault_enqueue(
            cu_storage_owner,
            NINLIL_TEST_STORAGE_OP_COMMIT,
            NINLIL_STORAGE_COMMIT_UNKNOWN,
            1u,
            1,
            1));
        (void)memset(clock.epoch, 0x78, 16u);
        work = 99u;
        CHECK(wifi_step_v1(adapter, 1u, &work)
            == WIFI_PRIVATE_STORAGE_COMMIT_UNKNOWN);
        CHECK(work == 0u);
        CHECK(ninlil_test_storage_live_handles(cu_storage_owner) == 0u);
        CHECK(ninlil_test_storage_live_transactions(cu_storage_owner) == 0u);
        CHECK(wifi_state_v1(adapter, &operational, &reason, &epoch)
            == WIFI_PRIVATE_OK);
        CHECK(operational == WIFI_OPERATIONAL_FENCED);
        CHECK(reason == WIFI_REASON_TRUSTED_CLOCK_INVALID);
        (void)memcpy(clock.epoch, original_epoch, 16u);
        clock.now_ms = 1001u;
        CHECK(wifi_drain_begin_v1(adapter) == WIFI_PRIVATE_OK);
        CHECK(wifi_step_v1(adapter, 64u, &work) == WIFI_PRIVATE_OK);
        CHECK(wifi_destroy_v1(adapter) == WIFI_PRIVATE_OK);
        free(allocation4);
        ninlil_test_storage_destroy(cu_storage_owner);
    }

    ninlil_test_storage_destroy(storage_owner);
    if (failures != 0) {
        return 1;
    }
    (void)printf("wifi_v1_adapter_lifecycle_test PASS\n");
    return 0;
}
