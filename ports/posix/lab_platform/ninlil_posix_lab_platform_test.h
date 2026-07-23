#ifndef NINLIL_POSIX_LAB_PLATFORM_TEST_H
#define NINLIL_POSIX_LAB_PLATFORM_TEST_H

/*
 * Test-only accessors for POSIX LAB platform conformance. Not installed.
 */

#include "canonical_origin_authorization.h"
#include "deterministic_entropy.h"
#include "ninlil_posix_lab_platform.h"
#include "platform_basic_fixtures.h"
#include "typed_simulated_bearer.h"

#ifdef __cplusplus
extern "C" {
#endif

ninlil_test_allocator_t *ninlil_posix_lab_platform_test_allocator(
    ninlil_posix_lab_platform_t *platform);
ninlil_test_execution_t *ninlil_posix_lab_platform_test_execution(
    ninlil_posix_lab_platform_t *platform);
ninlil_test_clock_t *ninlil_posix_lab_platform_test_clock(
    ninlil_posix_lab_platform_t *platform);
ninlil_test_entropy_t *ninlil_posix_lab_platform_test_entropy(
    ninlil_posix_lab_platform_t *platform);
ninlil_test_bearer_t *ninlil_posix_lab_platform_test_bearer(
    ninlil_posix_lab_platform_t *platform);
ninlil_test_origin_auth_t *ninlil_posix_lab_platform_test_origin(
    ninlil_posix_lab_platform_t *platform);

int ninlil_posix_lab_platform_test_loopback_connected(
    ninlil_posix_lab_platform_t *platform);
uint64_t ninlil_posix_lab_platform_test_inject_send_count(
    ninlil_posix_lab_platform_t *platform);
uint64_t ninlil_posix_lab_platform_test_inject_recv_count(
    ninlil_posix_lab_platform_t *platform);
uint64_t ninlil_posix_lab_platform_test_inject_drop_count(
    ninlil_posix_lab_platform_t *platform);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_LAB_PLATFORM_TEST_H */
