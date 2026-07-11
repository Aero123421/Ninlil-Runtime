#ifndef NINLIL_TEST_DETERMINISTIC_ENTROPY_H
#define NINLIL_TEST_DETERMINISTIC_ENTROPY_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_TEST_ENTROPY_ACTION_CAPACITY ((size_t)32u)
#define NINLIL_TEST_ENTROPY_TRACE_CAPACITY ((size_t)1024u)

typedef struct ninlil_test_entropy ninlil_test_entropy_t;

typedef enum ninlil_test_entropy_action_kind {
    NINLIL_TEST_ENTROPY_ACTION_NONE = 0,
    NINLIL_TEST_ENTROPY_ACTION_TEMPORARY = 1,
    NINLIL_TEST_ENTROPY_ACTION_PERMANENT = 2,
    NINLIL_TEST_ENTROPY_ACTION_PARTIAL = 3,
    NINLIL_TEST_ENTROPY_ACTION_ALL_ZERO = 4
} ninlil_test_entropy_action_kind_t;

typedef struct ninlil_test_entropy_trace_record {
    uint64_t sequence;
    ninlil_test_entropy_action_kind_t action;
    ninlil_port_status_t status;
    uint32_t requested_length;
    uint32_t bytes_written;
    uint64_t counter_before;
    uint64_t counter_after;
    uint32_t exhausted_before;
    uint32_t exhausted_after;
    uint32_t script_configuration_error;
} ninlil_test_entropy_trace_record_t;

ninlil_test_entropy_t *ninlil_test_entropy_create(
    uint64_t seed,
    uint32_t stream_id);
const ninlil_entropy_ops_t *ninlil_test_entropy_ops(
    ninlil_test_entropy_t *entropy);
int ninlil_test_entropy_script(
    ninlil_test_entropy_t *entropy,
    ninlil_test_entropy_action_kind_t action,
    uint32_t partial_prefix_length,
    uint32_t remaining_count);
uint64_t ninlil_test_entropy_counter(const ninlil_test_entropy_t *entropy);
int ninlil_test_entropy_exhausted(const ninlil_test_entropy_t *entropy);
uint64_t ninlil_test_entropy_call_count(const ninlil_test_entropy_t *entropy);
uint64_t ninlil_test_entropy_script_error_count(
    const ninlil_test_entropy_t *entropy);
uint64_t ninlil_test_entropy_invalid_call_count(
    const ninlil_test_entropy_t *entropy);
int ninlil_test_entropy_trace_overflowed(
    const ninlil_test_entropy_t *entropy);
uint64_t ninlil_test_entropy_restart_count(
    const ninlil_test_entropy_t *entropy);
size_t ninlil_test_entropy_trace_count(const ninlil_test_entropy_t *entropy);
const ninlil_test_entropy_trace_record_t *ninlil_test_entropy_trace_at(
    const ninlil_test_entropy_t *entropy,
    size_t index);
void ninlil_test_entropy_simulate_restart(ninlil_test_entropy_t *entropy);
void ninlil_test_entropy_scenario_reset(
    ninlil_test_entropy_t *entropy,
    uint64_t seed,
    uint32_t stream_id);
int ninlil_test_entropy_set_counter_for_test(
    ninlil_test_entropy_t *entropy,
    uint64_t counter,
    int exhausted);
void ninlil_test_entropy_destroy(ninlil_test_entropy_t *entropy);

#ifdef __cplusplus
}
#endif

#endif
