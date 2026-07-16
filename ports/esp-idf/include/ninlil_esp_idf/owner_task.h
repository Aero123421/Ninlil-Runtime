/*
 * Port-owned FreeRTOS owner-task API (experimental).
 * Storage: owner_task_storage.h
 * Spec: docs/22
 */

#ifndef NINLIL_ESP_IDF_OWNER_TASK_H
#define NINLIL_ESP_IDF_OWNER_TASK_H

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH ((uint32_t)16u)
#define NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES ((uint32_t)48u)
#define NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES ((uint32_t)4096u)
/* Normative: concurrent tx-gate leases per owner object. */
#define NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES ((uint32_t)4u)

#define NINLIL_ESP_IDF_OWNER_MSG_NONE ((uint8_t)0u)
#define NINLIL_ESP_IDF_OWNER_MSG_TICK ((uint8_t)2u)
#define NINLIL_ESP_IDF_OWNER_MSG_CONTROL_SUMMARY ((uint8_t)3u)
#define NINLIL_ESP_IDF_OWNER_MSG_ASSIGNMENT ((uint8_t)4u)
#define NINLIL_ESP_IDF_OWNER_MSG_SELF_STOP_PROBE ((uint8_t)5u)

#define NINLIL_ESP_IDF_OWNER_LC_STOPPED ((uint8_t)0u)
#define NINLIL_ESP_IDF_OWNER_LC_STARTING ((uint8_t)1u)
#define NINLIL_ESP_IDF_OWNER_LC_RUNNING ((uint8_t)2u)
#define NINLIL_ESP_IDF_OWNER_LC_STOPPING ((uint8_t)3u)
#define NINLIL_ESP_IDF_OWNER_LC_JOIN_ACK ((uint8_t)4u)
#define NINLIL_ESP_IDF_OWNER_LC_FAILED_LIVE ((uint8_t)5u)
#define NINLIL_ESP_IDF_OWNER_LC_FAILED_JOINED ((uint8_t)6u)

typedef uint32_t ninlil_esp_idf_owner_status_t;

#define NINLIL_ESP_IDF_OWNER_OK ((ninlil_esp_idf_owner_status_t)0u)
#define NINLIL_ESP_IDF_OWNER_INVALID_ARGUMENT \
    ((ninlil_esp_idf_owner_status_t)1u)
#define NINLIL_ESP_IDF_OWNER_INVALID_STATE ((ninlil_esp_idf_owner_status_t)2u)
#define NINLIL_ESP_IDF_OWNER_WRONG_CONTEXT ((ninlil_esp_idf_owner_status_t)3u)
#define NINLIL_ESP_IDF_OWNER_STALE_GENERATION \
    ((ninlil_esp_idf_owner_status_t)4u)
#define NINLIL_ESP_IDF_OWNER_MAILBOX_FULL ((ninlil_esp_idf_owner_status_t)5u)
#define NINLIL_ESP_IDF_OWNER_MAILBOX_EMPTY ((ninlil_esp_idf_owner_status_t)6u)
#define NINLIL_ESP_IDF_OWNER_GENERATION_WRAP \
    ((ninlil_esp_idf_owner_status_t)7u)
#define NINLIL_ESP_IDF_OWNER_DOUBLE_START ((ninlil_esp_idf_owner_status_t)8u)
#define NINLIL_ESP_IDF_OWNER_DOUBLE_STOP ((ninlil_esp_idf_owner_status_t)9u)
#define NINLIL_ESP_IDF_OWNER_POISON ((ninlil_esp_idf_owner_status_t)10u)
#define NINLIL_ESP_IDF_OWNER_ISR_DENIED ((ninlil_esp_idf_owner_status_t)11u)
#define NINLIL_ESP_IDF_OWNER_SELF_STOP ((ninlil_esp_idf_owner_status_t)12u)
#define NINLIL_ESP_IDF_OWNER_TIMEOUT ((ninlil_esp_idf_owner_status_t)13u)
#define NINLIL_ESP_IDF_OWNER_NOT_ACCEPTING ((ninlil_esp_idf_owner_status_t)14u)
#define NINLIL_ESP_IDF_OWNER_BUSY ((ninlil_esp_idf_owner_status_t)15u)
#define NINLIL_ESP_IDF_OWNER_INFLIGHT_OVERFLOW \
    ((ninlil_esp_idf_owner_status_t)16u)
#define NINLIL_ESP_IDF_OWNER_LEASE_STALE ((ninlil_esp_idf_owner_status_t)17u)
#define NINLIL_ESP_IDF_OWNER_LEASE_FULL ((ninlil_esp_idf_owner_status_t)18u)
#define NINLIL_ESP_IDF_OWNER_TOKEN_EXHAUSTED \
    ((ninlil_esp_idf_owner_status_t)19u)

typedef struct ninlil_esp_idf_owner_msg {
    uint8_t kind;
    uint8_t flags;
    uint16_t payload_len;
    uint32_t generation;
    uint8_t payload[NINLIL_ESP_IDF_OWNER_MSG_PAYLOAD_BYTES];
} ninlil_esp_idf_owner_msg_t;

typedef struct ninlil_esp_idf_owner_control_summary {
    uint8_t frame_type;
    uint8_t reserved_zero;
    uint16_t payload_length;
    uint32_t stream_or_cell_id;
    uint32_t sequence;
} ninlil_esp_idf_owner_control_summary_t;

typedef struct ninlil_esp_idf_cell_assignment {
    uint32_t cell_id;
    uint16_t channel_id;
    uint16_t reserved_zero;
    ninlil_role_t role;
    uint32_t assignment_epoch;
    uint32_t controller_term;
} ninlil_esp_idf_cell_assignment_t;

typedef struct ninlil_esp_idf_owner_producer_stats {
    uint32_t posts_ok;
    uint32_t posts_full;
    uint32_t isr_denied;
    uint32_t stale_or_not_accepting;
    uint32_t poison;
    uint32_t inflight_overflow;
} ninlil_esp_idf_owner_producer_stats_t;

typedef struct ninlil_esp_idf_owner_owner_stats {
    uint32_t ticks_applied;
    uint32_t assignments_applied;
    uint32_t control_summaries_applied;
    uint32_t stale_apply;
    uint32_t wrong_context;
    uint32_t poison;
    uint32_t self_stop_probes;
} ninlil_esp_idf_owner_owner_stats_t;

typedef struct ninlil_esp_idf_owner_snapshot {
    uint8_t lifecycle;
    uint8_t accepting;
    uint16_t reserved_zero;
    uint32_t generation;
    uint32_t inflight_posts;
    uint32_t stack_hwm_bytes;
    uint32_t tcb_generation;
    uint32_t tx_gate_epoch;
    uint32_t tx_gate_borrowers;
    ninlil_esp_idf_owner_producer_stats_t producer;
    ninlil_esp_idf_owner_owner_stats_t owner;
} ninlil_esp_idf_owner_snapshot_t;

typedef struct ninlil_esp_idf_owner_core {
    uint8_t lifecycle;
    uint8_t reserved0;
    uint16_t reserved1;
    uint32_t generation;
    uint64_t owner_context_id;
    ninlil_esp_idf_owner_owner_stats_t stats;
    uint8_t assignment_present;
    uint8_t reserved2[3];
    ninlil_esp_idf_cell_assignment_t assignment;
} ninlil_esp_idf_owner_core_t;

typedef struct ninlil_esp_idf_owner_pure_mailbox {
    uint32_t head;
    uint32_t tail;
    uint32_t count;
    ninlil_esp_idf_owner_msg_t slots[NINLIL_ESP_IDF_OWNER_MAILBOX_DEPTH];
} ninlil_esp_idf_owner_pure_mailbox_t;

typedef struct ninlil_esp_idf_owner_task_config {
    NINLIL_STRUCT_HEADER;
    uint32_t task_priority;
    uint32_t reserved_zero;
} ninlil_esp_idf_owner_task_config_t;

/*
 * Gate lease: single-use identity (token+epoch+ops) while held.
 * Registry/slot layout is unstable detail only
 * (ninlil_esp_idf/detail/tx_gate_lease_registry.h).
 *
 * ABI staging + non-overlap (docs/22):
 * - struct_size-bearing inputs (owner config, tx_gate ops): stage 4-byte ABI
 *   header first; require abi_version + struct_size >= known minimum; reject
 *   declared full range (not fixed sizeof) overlap with owner storage via
 *   uintptr helper; then copy only known prefix to a local; never re-read
 *   caller tail after owner writes.
 * - fixed-size args (assignment, control summary, lease, snapshot out): full
 *   object non-overlap vs owner storage.
 * Violation → INVALID_ARGUMENT (or init fail); outputs/state unchanged.
 */
typedef struct ninlil_esp_idf_tx_gate_lease {
    uint32_t token;
    uint32_t epoch;
    const ninlil_tx_gate_ops_t *ops; /* valid while lease held */
} ninlil_esp_idf_tx_gate_lease_t;

typedef struct ninlil_esp_idf_owner_task ninlil_esp_idf_owner_task_t;

int ninlil_esp_idf_owner_task_init(
    ninlil_esp_idf_owner_task_t *task,
    const ninlil_esp_idf_owner_task_config_t *config);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_start(
    ninlil_esp_idf_owner_task_t *task);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_stop(
    ninlil_esp_idf_owner_task_t *task);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_tick(
    ninlil_esp_idf_owner_task_t *task);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_tick_from_isr(
    ninlil_esp_idf_owner_task_t *task);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_assignment(
    ninlil_esp_idf_owner_task_t *task,
    const ninlil_esp_idf_cell_assignment_t *assignment);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_control_summary(
    ninlil_esp_idf_owner_task_t *task,
    const ninlil_esp_idf_owner_control_summary_t *summary);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_post_self_stop_probe(
    ninlil_esp_idf_owner_task_t *task);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_get_snapshot(
    ninlil_esp_idf_owner_task_t *task,
    ninlil_esp_idf_owner_snapshot_t *out);

/* Tx gate lease (owner mux authority). */
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_acquire_tx_gate_lease(
    ninlil_esp_idf_owner_task_t *task,
    ninlil_esp_idf_tx_gate_lease_t *out_lease);
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_release_tx_gate_lease(
    ninlil_esp_idf_owner_task_t *task,
    const ninlil_esp_idf_tx_gate_lease_t *lease);

/* Idle-only set; requires borrowers==0. Validation of ops is lock-out. */
ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_set_tx_gate(
    ninlil_esp_idf_owner_task_t *task,
    const ninlil_tx_gate_ops_t *tx_gate);

ninlil_esp_idf_owner_status_t ninlil_esp_idf_owner_task_shutdown(
    ninlil_esp_idf_owner_task_t *task);

int ninlil_esp_idf_tx_gate_ops_validate(const ninlil_tx_gate_ops_t *ops);

#ifdef __cplusplus
}
#endif

#endif
