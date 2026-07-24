#ifndef NINLIL_POSIX_LOOPBACK_BEARER_WIRE_H
#define NINLIL_POSIX_LOOPBACK_BEARER_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_LOOPBACK_WIRE_MAGIC 0x4b424c4eu /* "NLBK" LE */
#define NINLIL_POSIX_LOOPBACK_WIRE_VERSION 1u

typedef struct ninlil_posix_loopback_wire_message {
    ninlil_bearer_message_t message;
    uint8_t *owned_payload;
    uint8_t *owned_evidence;
    uint8_t *owned_namespace_id;
    uint8_t *owned_service_id;
    uint8_t *owned_schema_id;
} ninlil_posix_loopback_wire_message_t;

void ninlil_posix_loopback_wire_message_init(
    ninlil_posix_loopback_wire_message_t *wire);

void ninlil_posix_loopback_wire_message_clear(
    ninlil_posix_loopback_wire_message_t *wire);

int ninlil_posix_loopback_wire_encode(
    const ninlil_bearer_message_t *message,
    uint8_t **out_bytes,
    size_t *out_length);

int ninlil_posix_loopback_wire_decode(
    const uint8_t *bytes,
    size_t length,
    ninlil_posix_loopback_wire_message_t *out_wire);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_POSIX_LOOPBACK_BEARER_WIRE_H */
