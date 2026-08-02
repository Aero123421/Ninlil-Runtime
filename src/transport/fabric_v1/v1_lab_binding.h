#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BINDING_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BINDING_H

/* Private exact LAB pair binding from ADR-0036. Not installed/public ABI. */

#include "r7_crypto_provider.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_BINDING_FIXED_BYTES ((size_t)420u)
#define NINLIL_V1_LAB_BINDING_MIN_BYTES ((size_t)557u)
#define NINLIL_V1_LAB_BINDING_MAX_BYTES ((size_t)966u)
#define NINLIL_V1_LAB_SERVICE_FIXED_BYTES ((size_t)134u)
#define NINLIL_V1_LAB_SERVICE_MAX ((uint8_t)3u)
#define NINLIL_V1_LAB_TEXT_MAX ((uint8_t)16u)

#define NINLIL_V1_LAB_FLOW_A_TO_B ((uint8_t)1u)
#define NINLIL_V1_LAB_FLOW_B_TO_A ((uint8_t)2u)
#define NINLIL_V1_LAB_SIDE_A ((uint8_t)1u)
#define NINLIL_V1_LAB_SIDE_B ((uint8_t)2u)

typedef uint32_t ninlil_v1_lab_binding_status_t;
#define NINLIL_V1_LAB_BINDING_OK ((ninlil_v1_lab_binding_status_t)0u)
#define NINLIL_V1_LAB_BINDING_INVALID_ARGUMENT \
    ((ninlil_v1_lab_binding_status_t)1u)
#define NINLIL_V1_LAB_BINDING_LENGTH ((ninlil_v1_lab_binding_status_t)2u)
#define NINLIL_V1_LAB_BINDING_STRUCTURAL ((ninlil_v1_lab_binding_status_t)3u)
#define NINLIL_V1_LAB_BINDING_SEMANTIC ((ninlil_v1_lab_binding_status_t)4u)
#define NINLIL_V1_LAB_BINDING_DIGEST ((ninlil_v1_lab_binding_status_t)5u)
#define NINLIL_V1_LAB_BINDING_CAPACITY ((ninlil_v1_lab_binding_status_t)6u)
#define NINLIL_V1_LAB_BINDING_ALIAS ((ninlil_v1_lab_binding_status_t)7u)
#define NINLIL_V1_LAB_BINDING_CRYPTO ((ninlil_v1_lab_binding_status_t)8u)

typedef struct ninlil_v1_lab_endpoint {
    uint8_t runtime_id[16];
    uint8_t application_id[16];
    uint8_t device_id[16];
    uint8_t installation_id[16];
    uint8_t site_id[16];
    uint64_t binding_epoch;
    uint64_t membership_epoch;
    uint32_t identity_flags;
    uint8_t clock_epoch_id[16];
    uint32_t clock_trust;
} ninlil_v1_lab_endpoint_t;

typedef struct ninlil_v1_lab_service_row {
    uint8_t slot;
    uint8_t flow;
    uint8_t namespace_length;
    uint8_t service_length;
    uint8_t schema_length;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[32];
    uint16_t schema_major;
    uint16_t schema_minor;
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint64_t evidence_grace_ms;
    uint8_t service_identity_digest[32];
    uint8_t path_policy_digest[32];
    uint8_t namespace_id[NINLIL_V1_LAB_TEXT_MAX];
    uint8_t service_id[NINLIL_V1_LAB_TEXT_MAX];
    uint8_t schema_id[NINLIL_V1_LAB_TEXT_MAX];
    /* Derived, off wire. */
    uint8_t selected_path_id[16];
    uint8_t policy_id[16];
} ninlil_v1_lab_service_row_t;

typedef struct ninlil_v1_lab_binding {
    uint8_t service_count;
    uint8_t controller_side; /* derived A or B */
    uint64_t pair_generation;
    ninlil_v1_lab_endpoint_t endpoint_a;
    ninlil_v1_lab_endpoint_t endpoint_b;
    uint8_t radio_site_domain_id[16];
    uint64_t radio_membership_epoch;
    uint32_t a_to_b_hop_context_id;
    uint32_t a_to_b_e2e_context_id;
    uint8_t a_to_b_hop_secret[32];
    uint8_t a_to_b_e2e_secret[32];
    uint32_t b_to_a_hop_context_id;
    uint32_t b_to_a_e2e_context_id;
    uint8_t b_to_a_hop_secret[32];
    uint8_t b_to_a_e2e_secret[32];
    ninlil_v1_lab_service_row_t services[NINLIL_V1_LAB_SERVICE_MAX];
    /* Derived, off wire. */
    uint8_t pair_id[32];
    uint8_t pair_binding_digest[32];
    uint8_t e2e_security_id[32];
    uint8_t raw[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    size_t raw_length;
} ninlil_v1_lab_binding_t;

/* Fill Service/policy digests and every off-wire derived field. */
ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_finalize(
    const ninlil_r7_crypto_provider *crypto,
    ninlil_v1_lab_binding_t *binding);

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_encode(
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_length);

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_decode(
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t *encoded,
    size_t encoded_length,
    ninlil_v1_lab_binding_t *out_binding);

ninlil_v1_lab_binding_status_t ninlil_v1_lab_binding_local_side(
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t runtime_id[16],
    uint8_t *out_side);

void ninlil_v1_lab_binding_clear(ninlil_v1_lab_binding_t *binding);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_BINDING_H */
