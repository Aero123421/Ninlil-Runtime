#include <ninlil/runtime.h>
#include <ninlil/service.h>
#include <ninlil/transaction.h>
#include <ninlil/platform.h>
#include <ninlil/version.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert(NINLIL_ABI_VERSION == 0x0001u, "ABI version mismatch");
_Static_assert(NINLIL_NO_DEADLINE == UINT64_MAX, "no deadline mismatch");
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
