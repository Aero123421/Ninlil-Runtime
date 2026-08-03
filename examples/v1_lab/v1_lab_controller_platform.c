#include "v1_lab_controller_platform.h"

#include "ninlil_posix_sqlite_storage.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

#define CONTROLLER_PLATFORM_MAGIC UINT32_C(0x4e435031)
#define CONTROLLER_PERMIT_LIFETIME_MS UINT64_C(5000)
#define CONTROLLER_LOGICAL_MESSAGE_BYTES_MAX UINT32_C(760)

struct ninlil_v1_lab_controller_platform {
    uint32_t magic;
    pthread_t owner_thread;
    uint64_t local_anchor_ms;
    uint64_t remote_anchor_ms;
    ninlil_id128_t clock_epoch_id;
    ninlil_posix_sqlite_storage_t *storage;
    ninlil_allocator_ops_t allocator;
    ninlil_execution_ops_t execution;
    ninlil_clock_ops_t clock;
    ninlil_entropy_ops_t entropy;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_platform_ops_t ops;
};

static void secure_clear(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;

    if (pointer == NULL) {
        return;
    }
    while (length > 0u) {
        *bytes = 0u;
        ++bytes;
        --length;
    }
}

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

static int power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static int monotonic_ms(uint64_t *out_ms)
{
    struct timespec value;
    uint64_t seconds;

    if (out_ms == NULL || clock_gettime(CLOCK_MONOTONIC, &value) != 0
        || value.tv_sec < 0 || value.tv_nsec < 0
        || value.tv_nsec >= 1000000000L) {
        return 0;
    }
    seconds = (uint64_t)value.tv_sec;
    if (seconds > UINT64_MAX / UINT64_C(1000)) {
        return 0;
    }
    *out_ms = seconds * UINT64_C(1000)
        + (uint64_t)value.tv_nsec / UINT64_C(1000000);
    return 1;
}

static int platform_valid(
    const ninlil_v1_lab_controller_platform_t *platform)
{
    return platform != NULL && platform->magic == CONTROLLER_PLATFORM_MAGIC
        && platform->storage != NULL;
}

static void *controller_allocate(
    void *user, uint64_t size, uint32_t alignment)
{
    void *result = NULL;
    size_t host_alignment;

    if (!platform_valid((ninlil_v1_lab_controller_platform_t *)user)
        || size == 0u || size > SIZE_MAX || !power_of_two(alignment)) {
        return NULL;
    }
    host_alignment = alignment < (uint32_t)sizeof(void *)
        ? sizeof(void *)
        : (size_t)alignment;
    if (posix_memalign(&result, host_alignment, (size_t)size) != 0) {
        return NULL;
    }
    return result;
}

static void controller_deallocate(
    void *user,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
{
    (void)size;
    (void)alignment;
    if (platform_valid((ninlil_v1_lab_controller_platform_t *)user)
        && pointer != NULL) {
        free(pointer);
    }
}

static uint64_t controller_context(void *user)
{
    ninlil_v1_lab_controller_platform_t *platform =
        (ninlil_v1_lab_controller_platform_t *)user;

    if (!platform_valid(platform)) {
        return 0u;
    }
    return pthread_equal(pthread_self(), platform->owner_thread) != 0
        ? UINT64_C(1)
        : UINT64_C(2);
}

static ninlil_port_status_t controller_clock_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    ninlil_v1_lab_controller_platform_t *platform =
        (ninlil_v1_lab_controller_platform_t *)user;
    uint64_t local_now;
    uint64_t elapsed;

    if (out_sample != NULL) {
        (void)memset(out_sample, 0, sizeof(*out_sample));
    }
    if (!platform_valid(platform) || out_sample == NULL
        || !monotonic_ms(&local_now) || local_now < platform->local_anchor_ms) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    elapsed = local_now - platform->local_anchor_ms;
    if (platform->remote_anchor_ms > UINT64_MAX - elapsed) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    out_sample->abi_version = NINLIL_ABI_VERSION;
    out_sample->struct_size = (uint16_t)sizeof(*out_sample);
    out_sample->clock_epoch_id = platform->clock_epoch_id;
    out_sample->now_ms = platform->remote_anchor_ms + elapsed;
    out_sample->trust = NINLIL_CLOCK_TRUSTED;
    return NINLIL_PORT_OK;
}

static ninlil_port_status_t controller_entropy_fill(
    void *user, uint8_t *out, uint32_t length)
{
    if (!platform_valid((ninlil_v1_lab_controller_platform_t *)user)
        || out == NULL || length == 0u || length > (uint32_t)INT_MAX) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    if (RAND_bytes(out, (int)length) != 1) {
        secure_clear(out, length);
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    return NINLIL_PORT_OK;
}

static int request_valid(
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now)
{
    uint32_t maximum;

    if (request == NULL || now == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || now->reserved_zero != 0u
        || !bytes_nonzero(request->transaction_id.bytes, 16u)
        || !bytes_nonzero(request->attempt_id.bytes, 16u)
        || !bytes_nonzero(now->clock_epoch_id.bytes, 16u)) {
        return 0;
    }
    if (request->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION
        || request->message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        maximum = CONTROLLER_LOGICAL_MESSAGE_BYTES_MAX;
    } else {
        return 0;
    }
    return request->logical_bytes != 0u && request->logical_bytes <= maximum;
}

static ninlil_tx_gate_status_t controller_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_v1_lab_controller_platform_t *platform =
        (ninlil_v1_lab_controller_platform_t *)user;

    if (out_permit != NULL) {
        (void)memset(out_permit, 0, sizeof(*out_permit));
    }
    if (!platform_valid(platform) || out_permit == NULL
        || !request_valid(request, now)
        || memcmp(now->clock_epoch_id.bytes,
               platform->clock_epoch_id.bytes, 16u)
            != 0
        || now->now_ms > UINT64_MAX - CONTROLLER_PERMIT_LIFETIME_MS) {
        return NINLIL_TX_GATE_DENIED;
    }
    out_permit->abi_version = NINLIL_ABI_VERSION;
    out_permit->struct_size = (uint16_t)sizeof(*out_permit);
    if (controller_entropy_fill(
            platform, out_permit->permit_id.bytes, 16u)
            != NINLIL_PORT_OK
        || !bytes_nonzero(out_permit->permit_id.bytes, 16u)) {
        secure_clear(out_permit, sizeof(*out_permit));
        return NINLIL_TX_GATE_TEMPORARY;
    }
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms =
        now->now_ms + CONTROLLER_PERMIT_LIFETIME_MS;
    return NINLIL_TX_GATE_OK;
}

static void controller_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t controller_origin_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    static const uint8_t provider_id[16] = {
        0x4eu, 0x69u, 0x6eu, 0x6cu, 0x69u, 0x6cu, 0x2du, 0x56u,
        0x31u, 0x2du, 0x4cu, 0x41u, 0x42u, 0x2du, 0x01u, 0x01u
    };
    static const uint8_t decision_digest[32] = {
        0xe2u, 0x47u, 0x23u, 0x6du, 0x79u, 0xeau, 0x1bu, 0xe3u,
        0x84u, 0xe0u, 0x89u, 0xd7u, 0x58u, 0xc7u, 0x38u, 0x08u,
        0x5bu, 0x4du, 0xe7u, 0x1fu, 0x71u, 0x9du, 0x60u, 0xa4u,
        0xbau, 0xb9u, 0x6du, 0xe0u, 0x93u, 0x37u, 0xc2u, 0x89u
    };

    if (out_decision != NULL) {
        (void)memset(out_decision, 0, sizeof(*out_decision));
    }
    if (!platform_valid((ninlil_v1_lab_controller_platform_t *)user)
        || request == NULL || out_decision == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || request->now.abi_version != NINLIL_ABI_VERSION
        || request->now.struct_size != (uint16_t)sizeof(request->now)
        || request->now.trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    out_decision->abi_version = NINLIL_ABI_VERSION;
    out_decision->struct_size = (uint16_t)sizeof(*out_decision);
    out_decision->allowed = 0u;
    out_decision->reason = NINLIL_REASON_UNSUPPORTED_DIRECTION;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    (void)memcpy(out_decision->provider_id.bytes, provider_id, 16u);
    out_decision->provider_revision = 1u;
    out_decision->decision_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(out_decision->decision_digest.bytes,
        decision_digest, 32u);
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void fill_ops(ninlil_v1_lab_controller_platform_t *platform)
{
    (void)memset(&platform->allocator, 0, sizeof(platform->allocator));
    platform->allocator.abi_version = NINLIL_ABI_VERSION;
    platform->allocator.struct_size = (uint16_t)sizeof(platform->allocator);
    platform->allocator.user = platform;
    platform->allocator.allocate = controller_allocate;
    platform->allocator.deallocate = controller_deallocate;

    (void)memset(&platform->execution, 0, sizeof(platform->execution));
    platform->execution.abi_version = NINLIL_ABI_VERSION;
    platform->execution.struct_size = (uint16_t)sizeof(platform->execution);
    platform->execution.user = platform;
    platform->execution.current_context_id = controller_context;

    (void)memset(&platform->clock, 0, sizeof(platform->clock));
    platform->clock.abi_version = NINLIL_ABI_VERSION;
    platform->clock.struct_size = (uint16_t)sizeof(platform->clock);
    platform->clock.user = platform;
    platform->clock.now = controller_clock_now;

    (void)memset(&platform->entropy, 0, sizeof(platform->entropy));
    platform->entropy.abi_version = NINLIL_ABI_VERSION;
    platform->entropy.struct_size = (uint16_t)sizeof(platform->entropy);
    platform->entropy.user = platform;
    platform->entropy.fill = controller_entropy_fill;

    (void)memset(&platform->tx_gate, 0, sizeof(platform->tx_gate));
    platform->tx_gate.abi_version = NINLIL_ABI_VERSION;
    platform->tx_gate.struct_size = (uint16_t)sizeof(platform->tx_gate);
    platform->tx_gate.user = platform;
    platform->tx_gate.acquire = controller_tx_acquire;
    platform->tx_gate.release_unused = controller_tx_release_unused;

    (void)memset(&platform->origin, 0, sizeof(platform->origin));
    platform->origin.abi_version = NINLIL_ABI_VERSION;
    platform->origin.struct_size = (uint16_t)sizeof(platform->origin);
    platform->origin.user = platform;
    platform->origin.evaluate = controller_origin_evaluate;

    (void)memset(&platform->ops, 0, sizeof(platform->ops));
    platform->ops.abi_version = NINLIL_ABI_VERSION;
    platform->ops.struct_size = (uint16_t)sizeof(platform->ops);
    platform->ops.allocator = &platform->allocator;
    platform->ops.execution = &platform->execution;
    platform->ops.clock = &platform->clock;
    platform->ops.entropy = &platform->entropy;
    platform->ops.storage = ninlil_posix_sqlite_storage_ops(platform->storage);
    platform->ops.bearer = NULL;
    platform->ops.tx_gate = &platform->tx_gate;
    platform->ops.origin_authorization = &platform->origin;
}

ninlil_v1_lab_controller_platform_t *
ninlil_v1_lab_controller_platform_create(
    const ninlil_v1_lab_controller_platform_config_t *config)
{
    ninlil_v1_lab_controller_platform_t *platform;
    ninlil_posix_sqlite_storage_config_t storage_config;

    if (config == NULL || config->database_path == NULL
        || config->database_path[0] == '\0'
        || !bytes_nonzero(config->clock_epoch_id, 16u)) {
        return NULL;
    }
    platform = (ninlil_v1_lab_controller_platform_t *)calloc(
        1u, sizeof(*platform));
    if (platform == NULL) {
        return NULL;
    }
    platform->magic = CONTROLLER_PLATFORM_MAGIC;
    platform->owner_thread = pthread_self();
    platform->remote_anchor_ms = config->clock_anchor_ms;
    (void)memcpy(platform->clock_epoch_id.bytes,
        config->clock_epoch_id, 16u);
    if (!monotonic_ms(&platform->local_anchor_ms)) {
        secure_clear(platform, sizeof(*platform));
        free(platform);
        return NULL;
    }

    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.database_path = config->database_path;
    storage_config.busy_timeout_ms =
        NINLIL_POSIX_SQLITE_DEFAULT_BUSY_TIMEOUT_MS;
    storage_config.max_entries_per_namespace = 512u;
    storage_config.max_bytes_per_namespace = UINT64_C(1048576);
    storage_config.max_handles = 8u;
    storage_config.max_transactions = 8u;
    storage_config.max_iterators = 8u;
    platform->storage = ninlil_posix_sqlite_storage_create(&storage_config);
    if (platform->storage == NULL) {
        secure_clear(platform, sizeof(*platform));
        free(platform);
        return NULL;
    }
    fill_ops(platform);
    return platform;
}

const ninlil_platform_ops_t *ninlil_v1_lab_controller_platform_ops(
    const ninlil_v1_lab_controller_platform_t *platform)
{
    return platform_valid(platform) ? &platform->ops : NULL;
}

void ninlil_v1_lab_controller_platform_destroy(
    ninlil_v1_lab_controller_platform_t *platform)
{
    if (!platform_valid(platform)
        || pthread_equal(pthread_self(), platform->owner_thread) == 0) {
        return;
    }
    ninlil_posix_sqlite_storage_destroy(platform->storage);
    platform->storage = NULL;
    secure_clear(platform, sizeof(*platform));
    free(platform);
}
