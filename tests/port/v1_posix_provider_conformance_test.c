/* V1-LAB unit 3: POSIX platform provider set conformance. */

#include "ninlil_posix_lab_platform_test.h"

#include <ninlil/runtime.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_factory_and_ops_wiring(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    REQUIRE(ninlil_posix_lab_platform_lifecycle(platform)
        == NINLIL_POSIX_LAB_PLATFORM_LIFECYCLE_ACTIVE);
    ops = ninlil_posix_lab_platform_ops(platform);
    REQUIRE(ops != NULL);
    REQUIRE(ops->allocator != NULL && ops->allocator->allocate != NULL
        && ops->allocator->deallocate != NULL);
    REQUIRE(ops->execution != NULL
        && ops->execution->current_context_id != NULL);
    REQUIRE(ops->clock != NULL && ops->clock->now != NULL);
    REQUIRE(ops->entropy != NULL && ops->entropy->fill != NULL);
    REQUIRE(ops->storage != NULL && ops->storage->open != NULL
        && ops->storage->close != NULL);
    REQUIRE(ops->bearer != NULL && ops->bearer->open != NULL
        && ops->bearer->close != NULL);
    REQUIRE(ops->tx_gate != NULL && ops->tx_gate->acquire != NULL
        && ops->tx_gate->release_unused != NULL);
    REQUIRE(ops->origin_authorization != NULL
        && ops->origin_authorization->evaluate != NULL);
    REQUIRE(ops->execution->current_context_id(ops->execution->user) != 0u);
    ninlil_posix_lab_platform_destroy(platform);
    ninlil_posix_lab_platform_destroy(NULL);
    return 0;
}

static int test_restart_cycle(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops_before;
    const ninlil_platform_ops_t *ops_after;
    const char *path_before;
    const char *path_after;
    ninlil_test_clock_t *clock_before;
    ninlil_time_sample_t sample;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    path_before = ninlil_posix_lab_platform_database_path(platform);
    ops_before = ninlil_posix_lab_platform_ops(platform);
    clock_before = ninlil_posix_lab_platform_test_clock(platform);
    REQUIRE(path_before != NULL && ops_before != NULL
        && ops_before->storage != NULL && clock_before != NULL);
    REQUIRE(ninlil_test_clock_script(
                clock_before, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u)
        == 1);
    REQUIRE(ninlil_posix_lab_platform_restart(platform) == 1);
    ops_after = ninlil_posix_lab_platform_ops(platform);
    path_after = ninlil_posix_lab_platform_database_path(platform);
    REQUIRE(ops_after != NULL && path_after != NULL && ops_after->storage != NULL);
    REQUIRE(strcmp(path_before, path_after) == 0);
    REQUIRE(ops_after->clock->now(ops_after->clock->user, &sample)
        == NINLIL_PORT_OK);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int test_allocator_fault(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;
    ninlil_test_allocator_t *allocator;
    void *ptr;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    allocator = ninlil_posix_lab_platform_test_allocator(platform);
    REQUIRE(ops != NULL && allocator != NULL);
    ninlil_test_allocator_fail_next(allocator, 1u);
    ptr = ops->allocator->allocate(ops->allocator->user, 16u, 8u);
    REQUIRE(ptr == NULL);
    ptr = ops->allocator->allocate(ops->allocator->user, 16u, 8u);
    REQUIRE(ptr != NULL);
    ops->allocator->deallocate(ops->allocator->user, ptr, 16u, 8u);
    ninlil_posix_lab_platform_destroy(platform);
    REQUIRE(ninlil_posix_lab_platform_restart(NULL) == 0);
    return 0;
}

static int test_entropy_fault(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;
    ninlil_test_entropy_t *entropy;
    uint8_t buffer[16];
    ninlil_port_status_t status;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    entropy = ninlil_posix_lab_platform_test_entropy(platform);
    REQUIRE(ops != NULL && entropy != NULL);
    REQUIRE(ninlil_test_entropy_script(
                entropy, NINLIL_TEST_ENTROPY_ACTION_PERMANENT, 0u, 1u)
        == 1);
    status = ops->entropy->fill(ops->entropy->user, buffer, 16u);
    REQUIRE(status == NINLIL_PORT_PERMANENT_FAILURE);
    status = ops->entropy->fill(ops->entropy->user, buffer, 16u);
    REQUIRE(status == NINLIL_PORT_OK);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int test_clock_fault(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;
    ninlil_test_clock_t *clock;
    ninlil_time_sample_t sample;
    ninlil_port_status_t status;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    clock = ninlil_posix_lab_platform_test_clock(platform);
    REQUIRE(ops != NULL && clock != NULL);
    REQUIRE(ninlil_test_clock_script(
                clock, NINLIL_PORT_TEMPORARY_FAILURE, NULL, 1u)
        == 1);
    status = ops->clock->now(ops->clock->user, &sample);
    REQUIRE(status == NINLIL_PORT_TEMPORARY_FAILURE);
    status = ops->clock->now(ops->clock->user, &sample);
    REQUIRE(status == NINLIL_PORT_OK);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int test_bearer_unavailable_fault(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;
    ninlil_test_bearer_t *bearer;
    ninlil_id128_t runtime_id;
    ninlil_bearer_handle_t handle = NULL;
    ninlil_bearer_status_t status;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    bearer = ninlil_posix_lab_platform_test_bearer(platform);
    REQUIRE(ops != NULL && bearer != NULL);
    REQUIRE(ninlil_test_bearer_raw_open_enqueue(
                bearer, NINLIL_BEARER_UNAVAILABLE, 0, 1u)
        == 1);
    (void)memset(&runtime_id, 0, sizeof(runtime_id));
    runtime_id.bytes[0] = 0x11u;
    status = ops->bearer->open(
        ops->bearer->user, &runtime_id, NINLIL_ROLE_CONTROLLER, &handle);
    REQUIRE(status == NINLIL_BEARER_UNAVAILABLE);
    REQUIRE(handle == NULL);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int test_origin_auth_evaluate(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    const ninlil_platform_ops_t *ops;
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_auth_status_t status;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    REQUIRE(ops != NULL);
    (void)memset(&request, 0, sizeof(request));
    request.abi_version = NINLIL_ABI_VERSION;
    request.struct_size = (uint16_t)sizeof(request);
    request.environment = NINLIL_ENV_TEST;
    request.now.abi_version = NINLIL_ABI_VERSION;
    request.now.struct_size = (uint16_t)sizeof(request.now);
    request.now.trust = NINLIL_CLOCK_TRUSTED;
    status = ops->origin_authorization->evaluate(
        ops->origin_authorization->user, &request, &decision);
    REQUIRE(status == NINLIL_ORIGIN_AUTH_OK || status
        == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

int main(void)
{
    if (test_factory_and_ops_wiring() != 0) {
        return 1;
    }
    if (test_restart_cycle() != 0) {
        return 1;
    }
    if (test_allocator_fault() != 0) {
        return 1;
    }
    if (test_entropy_fault() != 0) {
        return 1;
    }
    if (test_clock_fault() != 0) {
        return 1;
    }
    if (test_bearer_unavailable_fault() != 0) {
        return 1;
    }
    if (test_origin_auth_evaluate() != 0) {
        return 1;
    }
    (void)printf("v1_posix_provider_conformance_test ok\n");
    return 0;
}
