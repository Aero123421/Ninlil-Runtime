/*
 * V1-LAB unit 3: POSIX LAB platform + runtime full restart E2E.
 * create→run→shutdown→platform restart→re-create cycle with durable storage.
 */

#include "ninlil_posix_lab_platform.h"
#include "runtime_lifecycle_model.h"

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

static const uint8_t TEST_NAMESPACE[] = "v1-posix-platform-restart-e2e";

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(first + index);
    }
}

static ninlil_runtime_config_t runtime_config_fixture(void)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, 0x10u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, 0x20u);
    set_id(&config.local_identity.installation_id, 0x40u);
    set_id(&config.local_identity.site_domain_id, 0x60u);
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = TEST_NAMESPACE;
    config.storage_namespace.length = sizeof(TEST_NAMESPACE) - 1u;
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 8u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes = 5000u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 8u;
    config.limits.max_nonterminal_deliveries = 8u;
    config.limits.max_result_cache_entries = 8u;
    config.limits.max_retained_dispositions = 8u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 8u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.limits.max_event_spool_count = 0u;
    config.limits.max_event_spool_bytes = 0u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 900u;
    config.observation_retention_ms = 800u;
    return config;
}

static int runtime_create_cycle(
    ninlil_posix_lab_platform_t *platform,
    ninlil_runtime_t **out_runtime,
    ninlil_model_runtime_validation_result_t *out_validation)
{
    const ninlil_platform_ops_t *ops;
    ninlil_runtime_config_t config;
    ninlil_status_t status;

    ops = ninlil_posix_lab_platform_ops(platform);
    if (ops == NULL) {
        return 0;
    }
    config = runtime_config_fixture();
    status = ninlil_model_runtime_validate_and_derive(
        &config, ops, out_validation);
    if (status != NINLIL_OK) {
        return 0;
    }
    status = ninlil_runtime_create(&config, ops, out_runtime);
    return status == NINLIL_OK && *out_runtime != NULL;
}

static int test_runtime_platform_restart_cycle(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    ninlil_runtime_t *runtime = NULL;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);

    REQUIRE(runtime_create_cycle(platform, &runtime, &validation));
    (void)memset(&budget, 0, sizeof(budget));
    budget.abi_version = NINLIL_ABI_VERSION;
    budget.struct_size = (uint16_t)sizeof(budget);
    budget.max_ingress_messages = 1u;
    budget.max_callbacks = 1u;
    budget.max_state_transitions = 1u;
    budget.max_bearer_sends = 1u;
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    runtime = NULL;

    REQUIRE(ninlil_posix_lab_platform_restart(platform) == 1);

    REQUIRE(runtime_create_cycle(platform, &runtime, &validation));
    (void)memset(&step_result, 0, sizeof(step_result));
    REQUIRE(ninlil_runtime_step(runtime, &budget, &step_result) == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);

    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

static int test_double_runtime_destroy_reject(void)
{
    ninlil_posix_lab_platform_config_t config;
    ninlil_posix_lab_platform_t *platform;
    ninlil_runtime_t *runtime = NULL;
    ninlil_model_runtime_validation_result_t validation;

    ninlil_posix_lab_platform_config_defaults(&config);
    platform = ninlil_posix_lab_platform_create(&config);
    REQUIRE(platform != NULL);
    REQUIRE(runtime_create_cycle(platform, &runtime, &validation));
    REQUIRE(ninlil_runtime_destroy(runtime) == NINLIL_OK);
    REQUIRE(ninlil_runtime_destroy(runtime) != NINLIL_OK);
    ninlil_posix_lab_platform_destroy(platform);
    return 0;
}

int main(void)
{
    if (test_runtime_platform_restart_cycle() != 0) {
        return 1;
    }
    if (test_double_runtime_destroy_reject() != 0) {
        return 1;
    }
    (void)printf("v1_posix_platform_restart_e2e_test ok\n");
    return 0;
}
