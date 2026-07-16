/* Host-pure tests for ESP-IDF adapter lifecycle and immutable ops contracts. */

#include "clock_init_logic.h"
#include "clock_logic.h"
#include "entropy_lifecycle_logic.h"
#include "entropy_logic.h"
#include "entropy_publish_logic.h"
#include "execution_init_logic.h"
#include "execution_logic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",       \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static ninlil_time_sample_t caller_sample(void)
{
    ninlil_time_sample_t sample;
    (void)memset(&sample, 0, sizeof(sample));
    sample.abi_version = NINLIL_ABI_VERSION;
    sample.struct_size = (uint16_t)sizeof(sample);
    return sample;
}

static ninlil_port_status_t stub_clock_now(
    void *user,
    ninlil_time_sample_t *out)
{
    ninlil_esp_idf_clock_t *clock = (ninlil_esp_idf_clock_t *)user;

    if (clock == NULL || clock->lifecycle != 1u) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    return ninlil_esp_idf_clock_apply_now(
        &clock->boot_epoch_id,
        42u,
        &clock->has_last_sample,
        &clock->last_now_ms,
        out);
}

static uint64_t stub_execution_context(void *user);
static ninlil_port_status_t stub_entropy_fill(
    void *user,
    uint8_t *out,
    uint32_t length);

static int test_clock_one_shot_retained_ops(void)
{
    ninlil_esp_idf_clock_t clock;
    ninlil_esp_idf_clock_t fresh_clock;
    ninlil_esp_idf_clock_config_t cfg;
    const ninlil_clock_ops_t *ops;
    ninlil_time_sample_t sample;
    ninlil_clock_ops_t saved_ops;
    ninlil_id128_t saved_epoch;

    (void)memset(&clock, 0, sizeof(clock));
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.abi_version = NINLIL_ABI_VERSION;
    cfg.struct_size = (uint16_t)sizeof(cfg);
    cfg.boot_epoch_id.bytes[0] = 0x11u;

    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &clock, &cfg, stub_clock_now)
        == 0);
    ops = ninlil_esp_idf_clock_ops_host(&clock);
    REQUIRE(ops == &clock.ops);
    saved_ops = *ops;
    saved_epoch = clock.boot_epoch_id;
    sample = caller_sample();
    REQUIRE(ops->now(ops->user, &sample) == NINLIL_PORT_OK);

    cfg.boot_epoch_id.bytes[0] = 0x22u;
    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &clock, &cfg, stub_clock_now)
        != 0);
    REQUIRE(memcmp(&saved_ops, &clock.ops, sizeof(saved_ops)) == 0);
    REQUIRE(memcmp(&saved_epoch, &clock.boot_epoch_id, sizeof(saved_epoch)) == 0);

    ninlil_esp_idf_clock_shutdown_host(&clock);
    REQUIRE(clock.lifecycle == 2u);
    REQUIRE(memcmp(&saved_ops, ops, sizeof(saved_ops)) == 0);
    sample = caller_sample();
    REQUIRE(ops->now(ops->user, &sample)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &clock, &cfg, stub_clock_now)
        != 0);

    /* A distinct zero-initialized object has an independent lifecycle. */
    (void)memset(&fresh_clock, 0, sizeof(fresh_clock));
    REQUIRE(&fresh_clock != &clock);
    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &fresh_clock, &cfg, stub_clock_now)
        == 0);
    return 0;
}

static int test_clock_short_config(void)
{
    ninlil_esp_idf_clock_config_view_t view;
    uint8_t *short_cfg;
    uint16_t abi = NINLIL_ABI_VERSION;
    uint16_t short_size = 4u;

    short_cfg = (uint8_t *)calloc(1u, 4u);
    REQUIRE(short_cfg != NULL);
    (void)memcpy(short_cfg, &abi, 2u);
    (void)memcpy(short_cfg + 2, &short_size, 2u);
    REQUIRE(!ninlil_esp_idf_clock_config_try_copy(short_cfg, &view));
    free(short_cfg);
    return 0;
}

static int test_clock_alias_safe_staged_config(void)
{
    union {
        ninlil_esp_idf_clock_t clock;
        ninlil_esp_idf_clock_config_t config;
    } storage;

    (void)memset(&storage, 0, sizeof(storage));
    storage.config.abi_version = NINLIL_ABI_VERSION;
    storage.config.struct_size = (uint16_t)sizeof(storage.config);
    storage.config.boot_epoch_id.bytes[0] = 0x7au;
    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &storage.clock, &storage.config, stub_clock_now)
        == 0);
    REQUIRE(storage.clock.boot_epoch_id.bytes[0] == 0x7au);
    return 0;
}

static int test_arbitrary_storage_is_not_init_authority(void)
{
    ninlil_esp_idf_clock_t clock;
    ninlil_esp_idf_clock_config_t config;
    ninlil_esp_idf_entropy_t entropy;
    ninlil_esp_idf_execution_t execution;

    (void)memset(&clock, 0xa5, sizeof(clock));
    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.boot_epoch_id.bytes[0] = 1u;
    REQUIRE(ninlil_esp_idf_clock_init_with_now(
            &clock, &config, stub_clock_now)
        != 0);

    (void)memset(&execution, 0xa5, sizeof(execution));
    REQUIRE(ninlil_esp_idf_execution_init_with_context(
            &execution, stub_execution_context)
        != 0);

    (void)memset(&entropy, 0xa5, sizeof(entropy));
    REQUIRE(!ninlil_esp_idf_entropy_storage_is_zero(&entropy));
    REQUIRE(ninlil_esp_idf_entropy_publish_once(
            &entropy,
            stub_entropy_fill,
            NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG,
            1u)
        != 0);
    return 0;
}

static uint64_t stub_execution_context(void *user)
{
    ninlil_esp_idf_execution_t *execution =
        (ninlil_esp_idf_execution_t *)user;
    return execution != NULL && execution->lifecycle == 1u ? 0x1234u : 0u;
}

static int test_execution_one_shot_retained_ops_and_isr(void)
{
    ninlil_esp_idf_execution_t execution;
    const ninlil_execution_ops_t *ops;
    ninlil_execution_ops_t saved;
    uint32_t handle = 0xabcdu;

    (void)memset(&execution, 0, sizeof(execution));
    REQUIRE(ninlil_esp_idf_execution_init_with_context(
            &execution, stub_execution_context)
        == 0);
    ops = &execution.ops;
    saved = *ops;
    REQUIRE(ops->current_context_id(ops->user) == 0x1234u);
    REQUIRE(ninlil_esp_idf_execution_init_with_context(
            &execution, stub_execution_context)
        != 0);
    ninlil_esp_idf_execution_shutdown_host(&execution);
    REQUIRE(memcmp(&saved, ops, sizeof(saved)) == 0);
    REQUIRE(ops->current_context_id(ops->user) == 0u);
    REQUIRE(ninlil_esp_idf_execution_init_with_context(
            &execution, stub_execution_context)
        != 0);
    REQUIRE(ninlil_esp_idf_execution_context_resolve(&handle, 1) == 0u);
    REQUIRE(ninlil_esp_idf_execution_context_resolve(&handle, 0)
        == (uint64_t)(uintptr_t)&handle);
    return 0;
}

static ninlil_port_status_t stub_entropy_fill(
    void *user,
    uint8_t *out,
    uint32_t length)
{
    ninlil_esp_idf_entropy_t *entropy =
        (ninlil_esp_idf_entropy_t *)user;
    if (length == 0u) {
        return NINLIL_PORT_OK;
    }
    if (entropy == NULL || entropy->ready == 0u || out == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    (void)memset(out, 0x5a, length);
    return NINLIL_PORT_OK;
}

static int test_entropy_retained_ops_immutable(void)
{
    ninlil_esp_idf_entropy_t entropy;
    const ninlil_entropy_ops_t *ops;
    ninlil_entropy_ops_t saved;
    uint8_t byte = 0u;

    (void)memset(&entropy, 0, sizeof(entropy));
    REQUIRE(ninlil_esp_idf_entropy_publish_once(
            &entropy,
            stub_entropy_fill,
            NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG,
            1u)
        == 0);
    ops = &entropy.ops;
    saved = *ops;
    REQUIRE(ops->fill(ops->user, &byte, 1u) == NINLIL_PORT_OK);
    ninlil_esp_idf_entropy_retire_storage(&entropy);
    REQUIRE(memcmp(&saved, ops, sizeof(saved)) == 0);
    REQUIRE(ops->fill(ops->user, &byte, 1u)
        == NINLIL_PORT_PERMANENT_FAILURE);
    REQUIRE(ninlil_esp_idf_entropy_publish_once(
            &entropy,
            stub_entropy_fill,
            NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG,
            2u)
        != 0);
    return 0;
}

static int test_entropy_acquiring_cancel_await_model(void)
{
    ninlil_esp_idf_entropy_lifecycle_t life;
    int instance = 1;
    int should_enable = 0;
    int can_disable = 0;
    int ignored = 0;

    (void)memset(&life, 0, sizeof(life));
    REQUIRE(ninlil_esp_idf_entropy_life_begin_acquire(
            &life, &instance, 1, &should_enable)
        == 0);
    REQUIRE(should_enable == 1);
    REQUIRE(ninlil_esp_idf_entropy_life_request_shutdown(
            &life, &instance, &can_disable)
        == NINLIL_ESP_IDF_ENTROPY_SD_CANCEL_ACQUIRE);
    REQUIRE(ninlil_esp_idf_entropy_life_complete_acquire(
            &life, &instance)
        == 2);
    REQUIRE(life.state == NINLIL_ESP_IDF_ENTROPY_LIFE_DISABLING);
    REQUIRE(!ninlil_esp_idf_entropy_life_is_serving_owner(
        &life, &instance));
    REQUIRE(ninlil_esp_idf_entropy_life_finish_disable(
            &life, &instance, &ignored)
        == 0);
    REQUIRE(life.state == NINLIL_ESP_IDF_ENTROPY_LIFE_RETIRED);
    REQUIRE(ninlil_esp_idf_entropy_life_begin_acquire(
            &life, &instance, 1, &should_enable)
        != 0);
    return 0;
}

static int test_entropy_blocking_drain_and_boot_once(void)
{
    ninlil_esp_idf_entropy_lifecycle_t life;
    int first = 1;
    int fresh_address = 2;
    int should_enable = 0;
    int can_disable = 0;
    int ignored = 0;

    (void)memset(&life, 0, sizeof(life));
    REQUIRE(ninlil_esp_idf_entropy_life_begin_acquire(
            &life, &first, 1, &should_enable)
        == 0);
    REQUIRE(ninlil_esp_idf_entropy_life_complete_acquire(&life, &first) == 0);
    REQUIRE(ninlil_esp_idf_entropy_life_begin_fill(&life, &first) == 0);
    REQUIRE(ninlil_esp_idf_entropy_life_begin_fill(&life, &first) == 0);
    REQUIRE(ninlil_esp_idf_entropy_life_request_shutdown(
            &life, &first, &can_disable)
        == NINLIL_ESP_IDF_ENTROPY_SD_BEGIN_RELEASE);
    REQUIRE(can_disable == 0);
    REQUIRE(!ninlil_esp_idf_entropy_life_release_drained(&life, &first));
    REQUIRE(ninlil_esp_idf_entropy_life_end_fill(&life, &first) == 0);
    REQUIRE(!ninlil_esp_idf_entropy_life_release_drained(&life, &first));
    REQUIRE(ninlil_esp_idf_entropy_life_end_fill(&life, &first) == 1);
    REQUIRE(ninlil_esp_idf_entropy_life_release_drained(&life, &first));
    REQUIRE(ninlil_esp_idf_entropy_life_begin_disable(&life, &first) == 0);
    REQUIRE(ninlil_esp_idf_entropy_life_finish_disable(
            &life, &first, &ignored)
        == 0);
    REQUIRE(life.state == NINLIL_ESP_IDF_ENTROPY_LIFE_RETIRED);
    REQUIRE(ninlil_esp_idf_entropy_life_begin_acquire(
            &life, &fresh_address, 1, &should_enable)
        != 0);
    return 0;
}

static int test_entropy_generation_wrap_fail_closed(void)
{
    ninlil_esp_idf_entropy_lifecycle_t life;
    int instance = 1;
    int should_enable = 0;

    (void)memset(&life, 0, sizeof(life));
    life.generation = UINT32_MAX;
    REQUIRE(ninlil_esp_idf_entropy_life_begin_acquire(
            &life, &instance, 1, &should_enable)
        != 0);
    REQUIRE(life.state == NINLIL_ESP_IDF_ENTROPY_LIFE_FREE);
    REQUIRE(should_enable == 0);
    return 0;
}

int main(void)
{
    if (test_clock_short_config() != 0
        || test_clock_alias_safe_staged_config() != 0
        || test_arbitrary_storage_is_not_init_authority() != 0
        || test_clock_one_shot_retained_ops() != 0
        || test_execution_one_shot_retained_ops_and_isr() != 0
        || test_entropy_retained_ops_immutable() != 0
        || test_entropy_acquiring_cancel_await_model() != 0
        || test_entropy_blocking_drain_and_boot_once() != 0
        || test_entropy_generation_wrap_fail_closed() != 0) {
        return 1;
    }
    return 0;
}
