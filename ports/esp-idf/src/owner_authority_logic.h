/*
 * Pure lifecycle authority model for host deterministic concurrency tests.
 * Mirrors docs/22 inflight + claim + FAILED_LIVE rules without FreeRTOS.
 */

#ifndef NINLIL_ESP_IDF_OWNER_AUTHORITY_LOGIC_H
#define NINLIL_ESP_IDF_OWNER_AUTHORITY_LOGIC_H

#include "ninlil_esp_idf/owner_task.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_esp_idf_owner_authority {
    uint32_t api_lifecycle;
    uint32_t op_claim;
    uint32_t next_claim;
    uint32_t accepting;
    uint32_t generation;
    uint8_t published_lifecycle;
    uint8_t start_gate;
    uint8_t will_suspend;
    uint8_t reclaim_closed;
    uint32_t inflight;
    uint32_t handle_live; /* 0/1 abstract */
} ninlil_esp_idf_owner_authority_t;

void ninlil_esp_idf_owner_authority_init(
    ninlil_esp_idf_owner_authority_t *a);

int ninlil_esp_idf_owner_authority_try_claim(
    ninlil_esp_idf_owner_authority_t *a,
    uint32_t *out_token);
void ninlil_esp_idf_owner_authority_release_claim(
    ninlil_esp_idf_owner_authority_t *a,
    uint32_t token);

/* Returns 0 if admitted and inflight++. */
int ninlil_esp_idf_owner_authority_admit_post(
    ninlil_esp_idf_owner_authority_t *a);
void ninlil_esp_idf_owner_authority_complete_post(
    ninlil_esp_idf_owner_authority_t *a);

/* Pure order: close admit → wait inflight0 → join → delete → stopped. */
int ninlil_esp_idf_owner_authority_begin_stop(
    ninlil_esp_idf_owner_authority_t *a);
int ninlil_esp_idf_owner_authority_can_reclaim(
    const ninlil_esp_idf_owner_authority_t *a);
void ninlil_esp_idf_owner_authority_mark_suspended(
    ninlil_esp_idf_owner_authority_t *a);
void ninlil_esp_idf_owner_authority_finish_join(
    ninlil_esp_idf_owner_authority_t *a);
void ninlil_esp_idf_owner_authority_timeout_failed_live(
    ninlil_esp_idf_owner_authority_t *a);
int ninlil_esp_idf_owner_authority_may_retire(
    const ninlil_esp_idf_owner_authority_t *a);
int ninlil_esp_idf_owner_authority_may_swap_tx(
    const ninlil_esp_idf_owner_authority_t *a);

#ifdef __cplusplus
}
#endif

#endif
