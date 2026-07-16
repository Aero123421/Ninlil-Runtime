/*
 * Backend-independent TaskHandle → context id conversion rules.
 * Host unit tests compile this without FreeRTOS headers.
 */

#ifndef NINLIL_ESP_IDF_EXECUTION_LOGIC_H
#define NINLIL_ESP_IDF_EXECUTION_LOGIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Compile-time width rule for FreeRTOS TaskHandle_t mapping.
 * Callers pass sizeof(TaskHandle_t); pure logic rejects oversized handles.
 */
int ninlil_esp_idf_execution_handle_width_ok(size_t handle_bytes);

/*
 * NULL handle → 0 (wrong-context / no task).
 * Non-NULL: zero-extend (uintptr_t)handle into uint64_t for comparison only.
 */
uint64_t ninlil_esp_idf_execution_context_from_handle(const void *handle);

/*
 * ISR fail-closed: if in_isr_context is non-zero, always return 0 and do not
 * treat any handle as an owner-task identity (ISR must not spoof owner).
 * Otherwise delegate to handle conversion.
 */
uint64_t ninlil_esp_idf_execution_context_resolve(
    const void *handle,
    int in_isr_context);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_EXECUTION_LOGIC_H */
