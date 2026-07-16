#ifndef NINLIL_ESP_IDF_OWNER_TASK_STORAGE_H
#define NINLIL_ESP_IDF_OWNER_TASK_STORAGE_H

#include "ninlil_esp_idf/owner_task.h"
#include "ninlil_esp_idf/detail/tx_gate_lease_registry.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_OWNER_NOTIFY_DATA ((uint32_t)1u)
#define NINLIL_ESP_IDF_OWNER_NOTIFY_STOP ((uint32_t)2u)
#define NINLIL_ESP_IDF_OWNER_NOTIFY_START ((uint32_t)4u)

#define NINLIL_ESP_IDF_OWNER_STACK_WORDS \
    (NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES / (uint32_t)sizeof(StackType_t))

_Static_assert(
    (NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES % sizeof(StackType_t)) == 0u,
    "stack bytes StackType aligned");
_Static_assert(sizeof(ninlil_esp_idf_owner_msg_t) <= 64u, "msg budget");

struct ninlil_esp_idf_owner_task {
    /* Must be initialised with portMUX_INITIALIZER before any critical. */
    portMUX_TYPE mux;
    uint8_t mux_ready; /* 1 after legal INITIALIZER */

    uint32_t api_lifecycle; /* 0 zero, 1 init, 2 retired */
    uint32_t task_priority;
    uint32_t op_claim;
    uint32_t next_claim_token;

    uint32_t accepting;
    uint32_t published_generation;
    uint8_t published_lifecycle;
    uint8_t start_gate;
    uint8_t will_suspend;
    uint8_t reclaim_closed;

    uint32_t inflight_posts;
    uint32_t stack_hwm_bytes;
    uint32_t tcb_generation;

    ninlil_esp_idf_tx_gate_lease_registry_t lease_reg;

    ninlil_esp_idf_owner_producer_stats_t producer_stats;
    ninlil_esp_idf_owner_core_t core;

    StaticTask_t task_tcb;
    StackType_t task_stack[NINLIL_ESP_IDF_OWNER_STACK_WORDS];
    StaticQueue_t queue_cb;
    uint8_t queue_storage[NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH
        * sizeof(ninlil_esp_idf_owner_msg_t)];
    TaskHandle_t task_handle;
    QueueHandle_t queue_handle;
};

#ifdef __cplusplus
}
#endif

#endif
