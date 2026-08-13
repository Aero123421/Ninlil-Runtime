/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ESP32-S3 executable contract probe for the installed Composition surface.
 * This translation unit intentionally includes no private Ninlil header.
 * A successful run is not a successful create or physical HIL: target flash
 * storage remains fail-closed at FULL commit until power-cut attestation.
 */
#include "ninlil/composition_v1.h"

#include <stdint.h>
#include <string.h>

int ninlil_composition_public_target_smoke(void)
{
    ninlil_composition_v1_t *composition = NULL;
    ninlil_runtime_t *runtime = NULL;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_composition_step_budget_v1_t budget;
    ninlil_composition_step_result_v1_t result;
    uint32_t workspace_bytes = 0u;
    uint32_t workspace_alignment = 0u;
    uint32_t done = 1u;

    if (ninlil_composition_v1_workspace_required(
            NINLIL_COMPOSITION_PROFILE_1,
            &workspace_bytes,
            &workspace_alignment)
            != NINLIL_OK
        || workspace_bytes == 0u
        || workspace_bytes > (256u * 1024u)
        || workspace_alignment == 0u
        || (workspace_alignment & (workspace_alignment - 1u)) != 0u) {
        return -1;
    }

    /* Exercise target-linked validation paths without faking durable create. */
    if (ninlil_composition_v1_create(
            NINLIL_COMPOSITION_PROFILE_1,
            NULL,
            NULL,
            NULL,
            workspace_bytes,
            &composition)
            != NINLIL_E_INVALID_ARGUMENT
        || composition != NULL) {
        return -2;
    }
    if (ninlil_composition_v1_runtime(NULL, &runtime)
            != NINLIL_E_INVALID_ARGUMENT
        || runtime != NULL) {
        return -3;
    }
    if (ninlil_composition_v1_fabric(NULL, &fabric)
            != NINLIL_E_INVALID_ARGUMENT
        || fabric != NULL) {
        return -4;
    }

    (void)memset(&budget, 0, sizeof(budget));
    budget.api_version = NINLIL_COMPOSITION_API_VERSION;
    budget.struct_size = (uint16_t)sizeof(budget);
    budget.runtime.abi_version = NINLIL_ABI_VERSION;
    budget.runtime.struct_size = (uint16_t)sizeof(budget.runtime);
    budget.fabric_work = 1u;
    (void)memset(&result, 0, sizeof(result));
    result.api_version = NINLIL_COMPOSITION_API_VERSION;
    result.struct_size = (uint16_t)sizeof(result);
    if (ninlil_composition_v1_step(NULL, &budget, &result)
            != NINLIL_E_INVALID_ARGUMENT) {
        return -5;
    }
    if (ninlil_composition_v1_close_begin(NULL)
            != NINLIL_E_INVALID_ARGUMENT) {
        return -6;
    }
    if (ninlil_composition_v1_close_poll(NULL, 1u, &done)
            != NINLIL_E_INVALID_ARGUMENT
        || done != 0u) {
        return -7;
    }
    if (ninlil_composition_v1_destroy(NULL)
            != NINLIL_E_INVALID_ARGUMENT) {
        return -8;
    }
    return 0;
}
