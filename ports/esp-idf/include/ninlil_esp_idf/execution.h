/*
 * Port-owned ESP-IDF execution-context factory (M3-basic).
 *
 * Caller zero-initializes this one-shot state. Embedded ops are immutable
 * after publication. ISR → context 0. Runtime borrowers are destroyed before
 * shutdown; task identities must not be compared across task deletion.
 *
 * Spec: docs/20-m3-basic-esp-idf-platform-adapters.md
 */

#ifndef NINLIL_ESP_IDF_EXECUTION_H
#define NINLIL_ESP_IDF_EXECUTION_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_execution {
    ninlil_execution_ops_t ops;
    uint32_t lifecycle; /* 0 zero-init, 1 active, 2 retired */
} ninlil_esp_idf_execution_t;

int ninlil_esp_idf_execution_init(ninlil_esp_idf_execution_t *execution);

void ninlil_esp_idf_execution_shutdown(ninlil_esp_idf_execution_t *execution);

const ninlil_execution_ops_t *ninlil_esp_idf_execution_ops(
    ninlil_esp_idf_execution_t *execution);

#ifdef __cplusplus
}
#endif

#endif
