#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_N6_OWNER_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_N6_OWNER_H

/*
 * Private V1 LAB binding -> N6 owner from ADR-0036.
 *
 * This is intentionally a narrow adapter, not a general token/provider API.
 * It is the sole production callsite for N6's accepted local-identity,
 * authority and fresh-install entries in the V1 LAB profile.
 */

#include "n6_context_store.h"
#include "r7_crypto_provider.h"
#include "r7_frag/r7_r2_authority_clock.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_N6_OWNER_MAGIC ((uint32_t)0x91c6a25bu)

typedef struct ninlil_v1_lab_n6_handles {
    ninlil_n6_handle_t a_to_b_hop;
    ninlil_n6_handle_t a_to_b_e2e;
    ninlil_n6_handle_t b_to_a_hop;
    ninlil_n6_handle_t b_to_a_e2e;
} ninlil_v1_lab_n6_handles_t;

typedef struct ninlil_v1_lab_n6_owner {
    uint32_t magic;
    uint8_t active;
    uint8_t booted;
    uint8_t fenced;
    uint8_t reserved_zero;
    ninlil_n6_t *n6;
    ninlil_n6_crypto_ops_t n6_crypto;
    ninlil_r7_crypto_provider r7_crypto;
    uint8_t local_runtime_id[16];
    uint8_t local_node_id[16];
    uint8_t authority_clock_epoch_id[16];
    uint8_t last_install_count;
} ninlil_v1_lab_n6_owner_t;

/*
 * Takes ownership of the V1 N6 bind sequence for an already initialized N6
 * object: storage -> crypto -> canonical local identity. Any failure requires
 * a fresh N6 object; the owner stays fenced.
 */
ninlil_n6_status_t ninlil_v1_lab_n6_owner_init(
    ninlil_v1_lab_n6_owner_t *owner,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const uint8_t local_runtime_id[16]);

/*
 * Trusted-private-caller boundary: result must be the direct, unmodified
 * output of the canonical R2 sampler in the same provisioning call chain.
 * This is source-provenance, not a cryptographic capability token.
 */
ninlil_n6_status_t ninlil_v1_lab_n6_owner_boot_from_class_d(
    ninlil_v1_lab_n6_owner_t *owner,
    const ninlil_r2_authority_clock_result_t *result);

/*
 * Decode and revalidate one exact ADR-0036 binding, then install four N6 rows.
 * Any install failure shuts down N6, zeroizes live keys and fences this owner.
 */
ninlil_n6_status_t ninlil_v1_lab_n6_owner_install_pair(
    ninlil_v1_lab_n6_owner_t *owner,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_v1_lab_n6_handles_t *out_handles);

int ninlil_v1_lab_n6_owner_is_fenced(
    const ninlil_v1_lab_n6_owner_t *owner);

/* Shuts down owned N6 state, zeroizes the adapter; storage teardown is external. */
void ninlil_v1_lab_n6_owner_clear(ninlil_v1_lab_n6_owner_t *owner);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_N6_OWNER_H */
