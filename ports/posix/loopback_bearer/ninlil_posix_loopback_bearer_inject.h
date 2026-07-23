#ifndef NINLIL_POSIX_LOOPBACK_BEARER_INJECT_H
#define NINLIL_POSIX_LOOPBACK_BEARER_INJECT_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_LOOPBACK_INJECT_MODE_NONE 0u
#define NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_ACK 1u
#define NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_DATA 2u
#define NINLIL_POSIX_LOOPBACK_INJECT_MODE_DUPLICATE 3u
#define NINLIL_POSIX_LOOPBACK_INJECT_MODE_DELAY 4u

typedef struct ninlil_posix_loopback_bearer_inject ninlil_posix_loopback_bearer_inject_t;

typedef struct ninlil_posix_loopback_bearer_inject_config {
    const ninlil_bearer_ops_t *inner_bearer;
    const ninlil_tx_gate_ops_t *inner_tx_gate;
    void *inner_user;
    uint64_t seed;
    uint32_t mode;
    uint32_t drop_budget;
    uint32_t duplicate_budget;
    uint32_t delay_steps;
} ninlil_posix_loopback_bearer_inject_config_t;

ninlil_posix_loopback_bearer_inject_t *ninlil_posix_loopback_bearer_inject_create(
    const ninlil_posix_loopback_bearer_inject_config_t *config);

void ninlil_posix_loopback_bearer_inject_destroy(
    ninlil_posix_loopback_bearer_inject_t *inject);

const ninlil_bearer_ops_t *ninlil_posix_loopback_bearer_inject_bearer_ops(
    ninlil_posix_loopback_bearer_inject_t *inject);

const ninlil_tx_gate_ops_t *ninlil_posix_loopback_bearer_inject_tx_gate_ops(
    ninlil_posix_loopback_bearer_inject_t *inject);

uint64_t ninlil_posix_loopback_bearer_inject_send_count(
    const ninlil_posix_loopback_bearer_inject_t *inject);

uint64_t ninlil_posix_loopback_bearer_inject_recv_count(
    const ninlil_posix_loopback_bearer_inject_t *inject);

uint64_t ninlil_posix_loopback_bearer_inject_drop_count(
    const ninlil_posix_loopback_bearer_inject_t *inject);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_LOOPBACK_BEARER_INJECT_H */
