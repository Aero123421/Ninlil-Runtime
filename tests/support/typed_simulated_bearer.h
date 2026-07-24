#ifndef NINLIL_TEST_TYPED_SIMULATED_BEARER_H
#define NINLIL_TEST_TYPED_SIMULATED_BEARER_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_TEST_BEARER_DEFAULT_QUEUE_ENTRIES ((uint64_t)64u)
#define NINLIL_TEST_BEARER_DEFAULT_QUEUE_BYTES ((uint64_t)131072u)
#define NINLIL_TEST_BEARER_DEFAULT_MAX_PERMITS ((uint32_t)128u)
#define NINLIL_TEST_BEARER_TRACE_CAPACITY ((size_t)2048u)
#define NINLIL_TEST_BEARER_RAW_QUEUE_CAPACITY ((size_t)16u)

typedef struct ninlil_test_bearer ninlil_test_bearer_t;

typedef enum ninlil_test_bearer_operation {
    NINLIL_TEST_BEARER_OP_OPEN = 0,
    NINLIL_TEST_BEARER_OP_CLOSE = 1,
    NINLIL_TEST_BEARER_OP_SEND = 2,
    NINLIL_TEST_BEARER_OP_RECEIVE = 3,
    NINLIL_TEST_BEARER_OP_RELEASE = 4,
    NINLIL_TEST_BEARER_OP_STATE = 5,
    NINLIL_TEST_BEARER_OP_TX_ACQUIRE = 6,
    NINLIL_TEST_BEARER_OP_TX_RELEASE = 7,
    NINLIL_TEST_BEARER_OP_COUNT = 8
} ninlil_test_bearer_operation_t;

typedef struct ninlil_test_bearer_config {
    uint64_t max_entries_per_direction;
    uint64_t max_bytes_per_direction;
    uint32_t max_permits;
    uint32_t reserved_zero;
    ninlil_id128_t permit_issuer_id;
    ninlil_id128_t initial_clock_epoch_id;
    uint64_t initial_time_ms;
} ninlil_test_bearer_config_t;

typedef struct ninlil_test_bearer_trace_record {
    uint64_t sequence;
    ninlil_test_bearer_operation_t operation;
    ninlil_bearer_status_t bearer_status;
    ninlil_tx_gate_status_t tx_gate_status;
    uint64_t handle_id;
    ninlil_id128_t runtime_id;
    ninlil_id128_t peer_runtime_id;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    uint64_t logical_bytes;
    uint64_t queued_entries;
    uint64_t queued_bytes;
    uint64_t availability_epoch;
    uint32_t raw_consumed;
    uint32_t violation;
} ninlil_test_bearer_trace_record_t;

ninlil_test_bearer_t *ninlil_test_bearer_create(
    const ninlil_test_bearer_config_t *config);
void ninlil_test_bearer_destroy(ninlil_test_bearer_t *bearer);

const ninlil_bearer_ops_t *ninlil_test_bearer_ops(
    ninlil_test_bearer_t *bearer);
const ninlil_tx_gate_ops_t *ninlil_test_bearer_tx_gate_ops(
    ninlil_test_bearer_t *bearer);

int ninlil_test_bearer_set_time(
    ninlil_test_bearer_t *bearer,
    ninlil_id128_t clock_epoch_id,
    uint64_t now_ms);
int ninlil_test_bearer_set_path_up(
    ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    int up);
int ninlil_test_bearer_set_path_epoch_for_test(
    ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    uint64_t epoch);
int ninlil_test_bearer_fail_next_copy_allocations(
    ninlil_test_bearer_t *bearer,
    uint32_t count);

int ninlil_test_bearer_logical_bytes(
    const ninlil_bearer_message_t *message,
    uint64_t *out_bytes);

int ninlil_test_bearer_raw_open_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    int return_handle,
    uint32_t count);
int ninlil_test_bearer_raw_send_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_send_result_t *result,
    uint32_t count);
int ninlil_test_bearer_raw_receive_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_message_t *message,
    uint32_t count);
int ninlil_test_bearer_raw_state_enqueue(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_status_t status,
    const ninlil_bearer_state_t *state,
    uint32_t count);

int ninlil_test_bearer_direction_accounting(
    const ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *from_runtime_id,
    uint64_t *out_entries,
    uint64_t *out_bytes);
uint64_t ninlil_test_bearer_live_loan_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_live_loan_bytes(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_orphan_loan_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_orphan_loan_bytes(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_live_handle_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_tombstoned_handle_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_violation_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_call_count(
    const ninlil_test_bearer_t *bearer,
    ninlil_test_bearer_operation_t operation);
uint64_t ninlil_test_bearer_permit_live_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_permit_consumed_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_permit_released_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_permit_expired_count(
    const ninlil_test_bearer_t *bearer);
uint64_t ninlil_test_bearer_permit_fenced_count(
    const ninlil_test_bearer_t *bearer);
size_t ninlil_test_bearer_trace_count(const ninlil_test_bearer_t *bearer);
int ninlil_test_bearer_trace_overflowed(const ninlil_test_bearer_t *bearer);
const ninlil_test_bearer_trace_record_t *ninlil_test_bearer_trace_at(
    const ninlil_test_bearer_t *bearer,
    size_t index);

/*
 * Test-only: enqueue a bearer message on the incoming queue for runtime_id
 * (integration topology C4/C5 transport delivery).
 */
int ninlil_test_bearer_deliver_to_runtime(
    ninlil_test_bearer_t *bearer,
    const ninlil_id128_t *to_runtime_id,
    const ninlil_bearer_message_t *message);

/*
 * Like bearer send but optional peer enqueue (integration C4/C5 transport).
 * enqueue_peer=0 validates/consumes permit without queueing to peer.
 */
ninlil_bearer_status_t ninlil_test_bearer_try_send(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result,
    int enqueue_peer);

void ninlil_test_bearer_set_defer_peer_enqueue(
    ninlil_test_bearer_t *bearer,
    int enabled);

/*
 * Integration gate (item 10b): consume permit without typed-bearer logical-byte
 * equality against runtime tx_request (external C4/C5 transport delivers).
 */
ninlil_bearer_status_t ninlil_test_bearer_integration_gate_send(
    ninlil_test_bearer_t *bearer,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif
