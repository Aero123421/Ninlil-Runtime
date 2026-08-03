#include "v1_lab_controller_platform.h"

#include <dirent.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 0;                                                          \
        }                                                                      \
    } while (0)

typedef struct thread_probe {
    const ninlil_execution_ops_t *execution;
    uint64_t context_id;
} thread_probe_t;

static void fill_bytes(uint8_t *out, size_t length, uint8_t seed)
{
    size_t i;

    for (i = 0u; i < length; ++i) {
        out[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u;
}

static void *probe_other_thread(void *user)
{
    thread_probe_t *probe = (thread_probe_t *)user;
    probe->context_id = probe->execution->current_context_id(
        probe->execution->user);
    return NULL;
}

static void cleanup_directory(const char *directory)
{
    DIR *stream;
    struct dirent *entry;

    if (directory == NULL) {
        return;
    }
    stream = opendir(directory);
    if (stream != NULL) {
        while ((entry = readdir(stream)) != NULL) {
            char path[768];
            int written;

            if (strcmp(entry->d_name, ".") == 0
                || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            written = snprintf(path, sizeof(path), "%s/%s",
                directory, entry->d_name);
            if (written > 0 && (size_t)written < sizeof(path)) {
                (void)unlink(path);
            }
        }
        (void)closedir(stream);
    }
    (void)rmdir(directory);
}

static int run_platform_contract(void)
{
    char directory[] = "/tmp/ninlil-controller-platform-XXXXXX";
    char database[640];
    ninlil_v1_lab_controller_platform_config_t config;
    ninlil_v1_lab_controller_platform_t *platform = NULL;
    const ninlil_platform_ops_t *ops;
    ninlil_time_sample_t now;
    ninlil_tx_request_t request;
    ninlil_tx_permit_t permit;
    ninlil_origin_authorization_request_t origin_request;
    ninlil_origin_authorization_decision_t decision;
    uint8_t entropy_a[32];
    uint8_t entropy_b[32];
    void *allocation;
    pthread_t thread;
    thread_probe_t probe;
    int written;

    REQUIRE(mkdtemp(directory) != NULL);
    written = snprintf(database, sizeof(database), "%s/runtime.sqlite3",
        directory);
    REQUIRE(written > 0 && (size_t)written < sizeof(database));
    (void)memset(&config, 0, sizeof(config));
    config.database_path = database;
    fill_bytes(config.clock_epoch_id, 16u, 0xa0u);
    config.clock_anchor_ms = UINT64_C(4000);
    platform = ninlil_v1_lab_controller_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_v1_lab_controller_platform_ops(platform);
    REQUIRE(ops != NULL && ops->allocator != NULL
        && ops->execution != NULL && ops->clock != NULL
        && ops->entropy != NULL && ops->storage != NULL
        && ops->bearer == NULL && ops->tx_gate != NULL
        && ops->origin_authorization != NULL);
    REQUIRE(ops->execution->current_context_id(ops->execution->user) == 1u);
    (void)memset(&probe, 0, sizeof(probe));
    probe.execution = ops->execution;
    REQUIRE(pthread_create(&thread, NULL, probe_other_thread, &probe) == 0);
    REQUIRE(pthread_join(thread, NULL) == 0);
    REQUIRE(probe.context_id == 2u);

    (void)memset(&now, 0, sizeof(now));
    REQUIRE(ops->clock->now(ops->clock->user, &now) == NINLIL_PORT_OK);
    REQUIRE(now.abi_version == NINLIL_ABI_VERSION
        && now.struct_size == (uint16_t)sizeof(now)
        && now.trust == NINLIL_CLOCK_TRUSTED && now.now_ms >= 4000u
        && memcmp(now.clock_epoch_id.bytes, config.clock_epoch_id, 16u) == 0);

    (void)memset(entropy_a, 0, sizeof(entropy_a));
    (void)memset(entropy_b, 0, sizeof(entropy_b));
    REQUIRE(ops->entropy->fill(
                ops->entropy->user, entropy_a, sizeof(entropy_a))
        == NINLIL_PORT_OK);
    REQUIRE(ops->entropy->fill(
                ops->entropy->user, entropy_b, sizeof(entropy_b))
        == NINLIL_PORT_OK);
    REQUIRE(bytes_nonzero(entropy_a, sizeof(entropy_a))
        && bytes_nonzero(entropy_b, sizeof(entropy_b))
        && memcmp(entropy_a, entropy_b, sizeof(entropy_a)) != 0);

    allocation = ops->allocator->allocate(ops->allocator->user, 257u, 64u);
    REQUIRE(allocation != NULL && (uintptr_t)allocation % 64u == 0u);
    ops->allocator->deallocate(ops->allocator->user, allocation, 257u, 64u);
    REQUIRE(ops->allocator->allocate(
        ops->allocator->user, 10u, 3u) == NULL);

    (void)memset(&request, 0, sizeof(request));
    request.abi_version = NINLIL_ABI_VERSION;
    request.struct_size = (uint16_t)sizeof(request);
    fill_bytes(request.transaction_id.bytes, 16u, 0x10u);
    fill_bytes(request.attempt_id.bytes, 16u, 0x30u);
    request.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    request.logical_bytes = 128u;
    (void)memset(&permit, 0, sizeof(permit));
    REQUIRE(ops->tx_gate->acquire(ops->tx_gate->user,
                &request, &now, &permit)
        == NINLIL_TX_GATE_OK);
    REQUIRE(bytes_nonzero(permit.permit_id.bytes, 16u)
        && memcmp(permit.attempt_id.bytes, request.attempt_id.bytes, 16u) == 0
        && memcmp(permit.clock_epoch_id.bytes, now.clock_epoch_id.bytes, 16u)
            == 0
        && permit.expires_at_ms > now.now_ms);
    request.logical_bytes = 129u;
    REQUIRE(ops->tx_gate->acquire(ops->tx_gate->user,
                &request, &now, &permit)
        == NINLIL_TX_GATE_DENIED);
    request.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    request.logical_bytes = 760u;
    REQUIRE(ops->tx_gate->acquire(ops->tx_gate->user,
                &request, &now, &permit)
        == NINLIL_TX_GATE_OK);

    (void)memset(&origin_request, 0, sizeof(origin_request));
    origin_request.abi_version = NINLIL_ABI_VERSION;
    origin_request.struct_size = (uint16_t)sizeof(origin_request);
    origin_request.environment = NINLIL_ENV_LAB;
    origin_request.now = now;
    (void)memset(&decision, 0, sizeof(decision));
    REQUIRE(ops->origin_authorization->evaluate(
                ops->origin_authorization->user,
                &origin_request, &decision)
        == NINLIL_ORIGIN_AUTH_OK);
    REQUIRE(decision.allowed == 0u
        && decision.reason == NINLIL_REASON_UNSUPPORTED_DIRECTION
        && decision.retry_guidance == NINLIL_RETRY_NEVER
        && bytes_nonzero(decision.provider_id.bytes, 16u)
        && decision.decision_digest.algorithm == NINLIL_DIGEST_SHA256
        && bytes_nonzero(decision.decision_digest.bytes, 32u)
        && decision.evaluated_at_ms == now.now_ms);

    ninlil_v1_lab_controller_platform_destroy(platform);
    platform = NULL;
    cleanup_directory(directory);
    return 1;
}

int main(void)
{
    if (!run_platform_contract()) {
        return 1;
    }
    (void)printf("v1_lab_controller_platform_test OK\n");
    return 0;
}
