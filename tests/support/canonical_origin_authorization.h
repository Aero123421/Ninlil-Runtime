#ifndef NINLIL_TEST_CANONICAL_ORIGIN_AUTHORIZATION_H
#define NINLIL_TEST_CANONICAL_ORIGIN_AUTHORIZATION_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_TEST_ORIGIN_AUTH_FAULT_CAPACITY ((size_t)16u)
#define NINLIL_TEST_ORIGIN_AUTH_TRACE_CAPACITY ((size_t)1024u)

typedef struct ninlil_test_origin_auth ninlil_test_origin_auth_t;

typedef struct ninlil_test_origin_auth_trace_record {
    uint64_t sequence;
    ninlil_origin_auth_status_t status;
    ninlil_environment_t environment;
    ninlil_id128_t event_id;
    uint64_t now_ms;
    uint64_t active_spool_bytes;
    uint32_t payload_length;
    uint32_t active_spool_count;
    uint32_t admissions_in_current_window;
    uint32_t allowed;
    ninlil_reason_t reason;
    uint32_t fault_consumed;
    uint32_t validation_failure;
} ninlil_test_origin_auth_trace_record_t;

ninlil_test_origin_auth_t *ninlil_test_origin_auth_create(void);
void ninlil_test_origin_auth_destroy(ninlil_test_origin_auth_t *provider);

const ninlil_origin_authorization_ops_t *ninlil_test_origin_auth_ops(
    ninlil_test_origin_auth_t *provider);

/*
 * Enqueue an exact raw evaluate outcome. A NULL decision means all-zero.
 * Only structurally valid TEST requests consume the bounded FIFO.
 */
int ninlil_test_origin_auth_raw_enqueue(
    ninlil_test_origin_auth_t *provider,
    ninlil_origin_auth_status_t status,
    const ninlil_origin_authorization_decision_t *decision,
    uint32_t count);

uint64_t ninlil_test_origin_auth_call_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_allow_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_deny_count(
    const ninlil_test_origin_auth_t *provider,
    ninlil_reason_t reason);
uint64_t ninlil_test_origin_auth_temporary_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_permanent_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_raw_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_validation_failure_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_fault_consumed_count(
    const ninlil_test_origin_auth_t *provider);
uint64_t ninlil_test_origin_auth_arithmetic_overflow_count(
    const ninlil_test_origin_auth_t *provider);
size_t ninlil_test_origin_auth_trace_count(
    const ninlil_test_origin_auth_t *provider);
int ninlil_test_origin_auth_trace_overflowed(
    const ninlil_test_origin_auth_t *provider);
const ninlil_test_origin_auth_trace_record_t *ninlil_test_origin_auth_trace_at(
    const ninlil_test_origin_auth_t *provider,
    size_t index);

#ifdef __cplusplus
}
#endif

#endif
