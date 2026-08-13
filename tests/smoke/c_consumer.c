/* SPDX-License-Identifier: Apache-2.0 */
#include <ninlil/runtime.h>
#include <ninlil/service.h>
#include <ninlil/transaction.h>
#include <ninlil/platform.h>
#include <ninlil/version.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert(NINLIL_ABI_VERSION == 0x0001u, "ABI version mismatch");
_Static_assert(NINLIL_NO_DEADLINE == UINT64_MAX, "no deadline mismatch");
_Static_assert(
    NINLIL_FOUNDATION_MAX_EXACT_TARGETS == 4u,
    "exact-target profile mismatch");
_Static_assert(NINLIL_ROLE_CONTROLLER == 1u, "controller role mismatch");
_Static_assert(NINLIL_ROLE_ENDPOINT == 2u, "endpoint role mismatch");
_Static_assert(NINLIL_ROLE_CELL_AGENT == 3u, "cell-agent role mismatch");
_Static_assert(
    NINLIL_ROLE_CELL_AGENT_RESERVED == NINLIL_ROLE_CELL_AGENT,
    "cell-agent compatibility alias mismatch");
_Static_assert(NINLIL_ENV_TEST == 1u, "test environment mismatch");
_Static_assert(NINLIL_ENV_LAB == 2u, "lab environment mismatch");
_Static_assert(NINLIL_ENV_FIELD == 3u, "field environment mismatch");
_Static_assert(
    NINLIL_ENV_PRODUCTION == 4u,
    "production environment mismatch");
_Static_assert(
    NINLIL_ENV_LAB_RESERVED == NINLIL_ENV_LAB,
    "lab compatibility alias mismatch");
_Static_assert(
    NINLIL_ENV_FIELD_RESERVED == NINLIL_ENV_FIELD,
    "field compatibility alias mismatch");
_Static_assert(
    NINLIL_ENV_PRODUCTION_RESERVED == NINLIL_ENV_PRODUCTION,
    "production compatibility alias mismatch");
_Static_assert(sizeof(ninlil_id128_t) == 16u, "id128 size mismatch");
_Static_assert(sizeof(ninlil_digest256_t) == 36u, "digest256 size mismatch");

static void exercise_abi_types(void)
{
    ninlil_runtime_config_t config = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = sizeof(ninlil_runtime_config_t),
    };
    ninlil_submission_result_t result = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = sizeof(ninlil_submission_result_t),
    };
    ninlil_step_budget_t budget = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = sizeof(ninlil_step_budget_t),
    };
    ninlil_capacity_snapshot_t capacity = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = sizeof(ninlil_capacity_snapshot_t),
        .entries = NULL,
        .entry_capacity = 0,
        .entry_count = 0,
    };

    (void)config;
    (void)result;
    (void)budget;
    (void)capacity;
}

int main(void)
{
    exercise_abi_types();
    return 0;
}
