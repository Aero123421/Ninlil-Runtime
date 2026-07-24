#ifndef NINLIL_POSIX_LOOPBACK_BEARER_H
#define NINLIL_POSIX_LOOPBACK_BEARER_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_LOOPBACK_BEARER_ROLE_SERVER 0u
#define NINLIL_POSIX_LOOPBACK_BEARER_ROLE_CLIENT 1u

typedef struct ninlil_posix_loopback_bearer ninlil_posix_loopback_bearer_t;

typedef struct ninlil_posix_loopback_bearer_config {
    const char *socket_path;
    uint32_t role;
    uint64_t max_entries_per_direction;
    uint64_t max_bytes_per_direction;
    uint32_t max_permits;
    ninlil_id128_t permit_issuer_id;
    ninlil_id128_t initial_clock_epoch_id;
    uint64_t initial_time_ms;
} ninlil_posix_loopback_bearer_config_t;

void ninlil_posix_loopback_bearer_config_defaults(
    ninlil_posix_loopback_bearer_config_t *config);

ninlil_posix_loopback_bearer_t *ninlil_posix_loopback_bearer_create(
    const ninlil_posix_loopback_bearer_config_t *config);

void ninlil_posix_loopback_bearer_destroy(ninlil_posix_loopback_bearer_t *bearer);

const ninlil_bearer_ops_t *ninlil_posix_loopback_bearer_ops(
    ninlil_posix_loopback_bearer_t *bearer);

const ninlil_tx_gate_ops_t *ninlil_posix_loopback_bearer_tx_gate_ops(
    ninlil_posix_loopback_bearer_t *bearer);

int ninlil_posix_loopback_bearer_set_time(
    ninlil_posix_loopback_bearer_t *bearer,
    ninlil_id128_t clock_epoch_id,
    uint64_t now_ms);

int ninlil_posix_loopback_bearer_connected(
    const ninlil_posix_loopback_bearer_t *bearer);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_LOOPBACK_BEARER_H */
