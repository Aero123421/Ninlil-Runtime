#ifndef NINLIL_RADIO_N6_CONTEXT_STORE_H
#define NINLIL_RADIO_N6_CONTEXT_STORE_H

/*
 * N6 private durable context store (docs/30 §5.3 / §9 / §20 Chunk D).
 *
 * SEMANTIC: N6_CHUNK_D_PRIVATE_HOST_CANDIDATE
 * SEMANTIC: N6_PRIVATE_ONLY_NO_PUBLIC_ABI
 * SEMANTIC: N6_FULL_OK_BEFORE_RAM_HANDLE
 * SEMANTIC: N6_DURABLE_TX_RX_FULL_REQUIRED
 * SEMANTIC: N6_CU_INTERNAL_CLASSIFY
 * SEMANTIC: N6_M4_REQUIRED_WITHOUT_AUTHENTICATED_CAPSULE
 * SEMANTIC: N6_M5_REQUIRED_FOR_SECRET_RESUME
 * SEMANTIC: N6_NO_HEAP_NO_VLA
 * SEMANTIC: N6_ESP_NOT_READY_NAMESPACE_CAPACITY
 *
 * Production-private. Not installed. Not R6 complete / not ESP N6 ready.
 * Fixture authority/install binders are NOT declared here. Conditional
 * NINLIL_N6_TEST_BUILD inspection hooks are declared at the end of this
 * private header and are absent from the production object/archive.
 */

#include "n6_crypto_provider.h"
#include "n6_record_codec.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Object / pool ceilings ---- */

#define NINLIL_N6_OBJECT_BYTES ((size_t)16384u)
#define NINLIL_N6_OBJECT_ALIGN ((size_t)8u)
/* Controller-class ceiling (docs/30 capacity table). Endpoint uses smaller. */
#define NINLIL_N6_POOL_MAX_SLOTS ((uint32_t)128u)
#define NINLIL_N6_POOL_MIN_SLOTS ((uint32_t)1u)
#define NINLIL_N6_TX_BLOCK_SIZE ((uint64_t)64u)
#define NINLIL_N6_RX_WINDOW ((uint32_t)64u)
#define NINLIL_N6_HINT_BYTES ((size_t)96u)
#define NINLIL_N6_MAX_LIVE_LEASES ((uint32_t)8u)
#define NINLIL_N6_MAX_LIVE_TICKETS ((uint32_t)8u)
#define NINLIL_N6_CU_PLAN_MAX_KEYS ((uint32_t)32u)

#define NINLIL_N6_ESP_NAMESPACES_REQUIRED ((uint32_t)3u)
#define NINLIL_N6_ESP_NAMESPACES_AVAILABLE ((uint32_t)2u)

#define NINLIL_N6_STORAGE_SCHEMA ((uint32_t)1u)
#define NINLIL_N6_NAMESPACE_BYTES ((size_t)12u)

/* ---- Status / reason / state ---- */

typedef uint32_t ninlil_n6_status_t;
typedef uint32_t ninlil_n6_reason_t;
typedef uint32_t ninlil_n6_state_t;

#define NINLIL_N6_OK ((ninlil_n6_status_t)0u)
#define NINLIL_N6_INVALID_ARGUMENT ((ninlil_n6_status_t)1u)
#define NINLIL_N6_INVALID_STATE ((ninlil_n6_status_t)2u)
#define NINLIL_N6_BUSY_REENTRY ((ninlil_n6_status_t)3u)
#define NINLIL_N6_M4_REQUIRED ((ninlil_n6_status_t)4u)
#define NINLIL_N6_M5_REQUIRED ((ninlil_n6_status_t)5u)
#define NINLIL_N6_STORAGE ((ninlil_n6_status_t)6u)
#define NINLIL_N6_CRYPTO ((ninlil_n6_status_t)7u)
#define NINLIL_N6_CAPACITY ((ninlil_n6_status_t)8u)
#define NINLIL_N6_FENCED ((ninlil_n6_status_t)9u)
#define NINLIL_N6_CORRUPT ((ninlil_n6_status_t)10u)
#define NINLIL_N6_COMMIT_UNKNOWN ((ninlil_n6_status_t)11u)
#define NINLIL_N6_UNSUPPORTED_ESP ((ninlil_n6_status_t)12u)
#define NINLIL_N6_ALIAS ((ninlil_n6_status_t)13u)
#define NINLIL_N6_SHUTDOWN ((ninlil_n6_status_t)14u)
#define NINLIL_N6_NOT_FOUND ((ninlil_n6_status_t)15u)
#define NINLIL_N6_TICKET ((ninlil_n6_status_t)16u)
#define NINLIL_N6_BOOT_DORMANT ((ninlil_n6_status_t)17u)
#define NINLIL_N6_LEASE ((ninlil_n6_status_t)18u)

#define NINLIL_N6_REASON_NONE ((ninlil_n6_reason_t)0u)
#define NINLIL_N6_REASON_NULL ((ninlil_n6_reason_t)1u)
#define NINLIL_N6_REASON_STATE ((ninlil_n6_reason_t)2u)
#define NINLIL_N6_REASON_REENTRY ((ninlil_n6_reason_t)3u)
#define NINLIL_N6_REASON_M4 ((ninlil_n6_reason_t)4u)
#define NINLIL_N6_REASON_M5 ((ninlil_n6_reason_t)5u)
#define NINLIL_N6_REASON_STORAGE ((ninlil_n6_reason_t)6u)
#define NINLIL_N6_REASON_CRYPTO ((ninlil_n6_reason_t)7u)
#define NINLIL_N6_REASON_CAPACITY ((ninlil_n6_reason_t)8u)
#define NINLIL_N6_REASON_FENCE ((ninlil_n6_reason_t)9u)
#define NINLIL_N6_REASON_CORRUPT ((ninlil_n6_reason_t)10u)
#define NINLIL_N6_REASON_COMMIT_UNKNOWN ((ninlil_n6_reason_t)11u)
#define NINLIL_N6_REASON_ESP ((ninlil_n6_reason_t)12u)
#define NINLIL_N6_REASON_ALIAS ((ninlil_n6_reason_t)13u)
#define NINLIL_N6_REASON_SHUTDOWN ((ninlil_n6_reason_t)14u)
#define NINLIL_N6_REASON_NOT_FOUND ((ninlil_n6_reason_t)15u)
#define NINLIL_N6_REASON_TICKET ((ninlil_n6_reason_t)16u)
#define NINLIL_N6_REASON_DORMANT ((ninlil_n6_reason_t)17u)
#define NINLIL_N6_REASON_PROVENANCE ((ninlil_n6_reason_t)18u)
#define NINLIL_N6_REASON_PROOF ((ninlil_n6_reason_t)19u)
#define NINLIL_N6_REASON_COUNTER ((ninlil_n6_reason_t)20u)
#define NINLIL_N6_REASON_DOMAIN ((ninlil_n6_reason_t)21u)
#define NINLIL_N6_REASON_LEASE ((ninlil_n6_reason_t)22u)
#define NINLIL_N6_REASON_STAMP ((ninlil_n6_reason_t)23u)
#define NINLIL_N6_REASON_CU_CLASS ((ninlil_n6_reason_t)24u)
#define NINLIL_N6_REASON_LOCAL_IDENTITY ((ninlil_n6_reason_t)25u)

#define NINLIL_N6_STATE_UNINIT ((ninlil_n6_state_t)0u)
#define NINLIL_N6_STATE_INIT ((ninlil_n6_state_t)1u)
#define NINLIL_N6_STATE_BOUND ((ninlil_n6_state_t)2u)
#define NINLIL_N6_STATE_BOOTED ((ninlil_n6_state_t)3u)
#define NINLIL_N6_STATE_DORMANT_DURABLE_NO_SECRET ((ninlil_n6_state_t)4u)
#define NINLIL_N6_STATE_READY ((ninlil_n6_state_t)5u)
#define NINLIL_N6_STATE_FENCED ((ninlil_n6_state_t)6u)
#define NINLIL_N6_STATE_SHUTDOWN ((ninlil_n6_state_t)7u)
#define NINLIL_N6_STATE_CU_PENDING ((ninlil_n6_state_t)8u)

/* Install provenance (production accepts only M4; fixture is test-only path). */
typedef uint32_t ninlil_n6_install_provenance_t;
#define NINLIL_N6_PROVENANCE_M4_AUTHENTICATED ((ninlil_n6_install_provenance_t)1u)
#define NINLIL_N6_PROVENANCE_FIXTURE_ONLY ((ninlil_n6_install_provenance_t)2u)

/* CU class (internal result; not a caller-trusted input). */
typedef uint32_t ninlil_n6_cu_class_t;
#define NINLIL_N6_CU_NONE ((ninlil_n6_cu_class_t)0u)
#define NINLIL_N6_CU_ALL_OLD ((ninlil_n6_cu_class_t)1u)
#define NINLIL_N6_CU_ALL_PROPOSED ((ninlil_n6_cu_class_t)2u)
#define NINLIL_N6_CU_MIXED ((ninlil_n6_cu_class_t)3u)
#define NINLIL_N6_CU_THIRD ((ninlil_n6_cu_class_t)4u)

typedef uint64_t ninlil_n6_handle_t;

typedef struct ninlil_n6 ninlil_n6_t;

typedef struct ninlil_n6_error {
    ninlil_n6_status_t status;
    ninlil_n6_reason_t reason;
    ninlil_n6_state_t state;
    ninlil_n6_cu_class_t last_cu_class;
    char hint[NINLIL_N6_HINT_BYTES];
} ninlil_n6_error_t;

typedef struct ninlil_n6_stats {
    uint64_t install_ok;
    uint64_t install_fail;
    uint64_t tx_burn_ok;
    uint64_t tx_burn_fail;
    uint64_t rx_precheck_ok;
    uint64_t rx_admit_ok;
    uint64_t rx_abort;
    uint64_t reentry_reject;
    uint64_t fence_count;
    uint64_t storage_fail;
    uint64_t commit_unknown;
    uint64_t dormant_boot;
    uint64_t corrupt_boot;
    uint64_t lease_release;
    uint64_t cu_recover_ok;
} ninlil_n6_stats_t;

/*
 * Opaque accepted-authority stamp fields (copy-in only).
 * Production: bind fails closed without R2 verifier / accepted-token adapter
 * (raw field values alone NEVER establish trust).
 * NINLIL_N6_TEST_BUILD host unit may inject a fixture stamp for tests.
 * N6 never samples OS time / R2 clock_ops.
 */
typedef struct ninlil_n6_authority_stamp {
    uint8_t clock_epoch_id[16];
    uint64_t now_ms;
    uint32_t trusted_class_d; /* opaque field; not a production trust oracle */
    uint32_t reserved0;
} ninlil_n6_authority_stamp_t;

/*
 * Private accepted local-identity adapter ABI (docs/30 §20.4.1).
 * Incomplete token; sole binder ninlil_n6_bind_local_identity_accepted.
 * No raw node_id / accepted_tag API. Public M4/R2 ABI unchanged.
 */
typedef struct ninlil_n6_accepted_local_identity_token
    ninlil_n6_accepted_local_identity_token_t;

typedef uint32_t ninlil_n6_local_identity_accept_status_t;
#define NINLIL_N6_LOCAL_ID_ACCEPT_OK ((ninlil_n6_local_identity_accept_status_t)0u)
#define NINLIL_N6_LOCAL_ID_ACCEPT_REJECTED ((ninlil_n6_local_identity_accept_status_t)1u)
#define NINLIL_N6_LOCAL_ID_ACCEPT_STALE ((ninlil_n6_local_identity_accept_status_t)2u)
#define NINLIL_N6_LOCAL_ID_ACCEPT_INTERNAL ((ninlil_n6_local_identity_accept_status_t)3u)

#define NINLIL_N6_LOCAL_ID_CLAIM_ABI ((uint16_t)1u)
#define NINLIL_N6_LOCAL_ID_CLAIM_BYTES ((uint16_t)24u)
#define NINLIL_N6_LOCAL_ID_OPS_ABI ((uint16_t)1u)

/*
 * Claim ABI v1 — exact 24 bytes (struct_size must equal CLAIM_BYTES).
 * Ops v1 — struct_size must equal sizeof(ninlil_n6_local_identity_ops_t).
 * Not forward-extensible at this R6 version; larger sizes require a later ADR.
 */
typedef struct ninlil_n6_local_identity_claim {
    uint16_t abi_version;
    uint16_t struct_size; /* == NINLIL_N6_LOCAL_ID_CLAIM_BYTES */
    uint32_t reserved_zero;
    uint8_t local_node_id[16];
} ninlil_n6_local_identity_claim_t;

typedef struct ninlil_n6_local_identity_ops {
    uint16_t abi_version;
    uint16_t struct_size; /* == sizeof(ninlil_n6_local_identity_ops_t) */
    uint32_t reserved_zero;
    void *user;
    ninlil_n6_local_identity_accept_status_t (*consume)(
        void *user,
        ninlil_n6_accepted_local_identity_token_t *mutable_token,
        ninlil_n6_local_identity_claim_t *claim_out);
} ninlil_n6_local_identity_ops_t;

typedef struct ninlil_n6_context_pool {
    uint32_t max_slots; /* 1..128 */
    uint32_t reserved_zero;
    void *bytes;
    size_t bytes_size;
} ninlil_n6_context_pool_t;

size_t ninlil_n6_context_pool_bytes(uint32_t max_slots);

typedef struct ninlil_n6_install_capsule {
    ninlil_n6_install_provenance_t provenance;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint8_t reserved0;
    uint32_t context_id;
    uint64_t membership_epoch;
    uint64_t key_generation;
    uint8_t binding_digest32[32];
    uint8_t traffic_secret32[32];
    uint8_t local_node_id[16];
    uint8_t receiver_node_id[16];
} ninlil_n6_install_capsule_t;

/*
 * TX crypto lease: copy-owned materials for W1 Seal.
 * Single-use: consume via release (or auto on admit path N/A); secure-zero on release.
 */
typedef struct ninlil_n6_tx_lease {
    uint64_t lease_id; /* nonzero */
    ninlil_n6_handle_t handle;
    uint8_t lane_kind; /* 1 DATA 2 ACK 3 E2E */
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t live;
    uint32_t context_id;
    uint64_t counter; /* first counter of reserved block */
    uint64_t block_end; /* exclusive end */
    uint8_t key16[16];
    uint8_t iv12[12];
    uint8_t reserved_pad[4];
} ninlil_n6_tx_lease_t;

/*
 * RX crypto ticket: materials for AEAD open; single-use abort/admit zeroizes.
 */
typedef struct ninlil_n6_rx_ticket {
    uint64_t ticket_id; /* nonzero */
    ninlil_n6_handle_t handle;
    uint8_t lane_kind;
    uint8_t layer_code;
    uint8_t direction_code;
    uint8_t live;
    uint32_t context_id;
    uint64_t counter;
    uint8_t key16[16];
    uint8_t iv12[12];
    uint8_t reserved_pad[4];
} ninlil_n6_rx_ticket_t;

/* ---- Lifecycle ---- */

ninlil_n6_status_t ninlil_n6_init(
    void *obj_bytes,
    size_t obj_size,
    ninlil_n6_context_pool_t *pool,
    ninlil_n6_t **out_n6);

ninlil_n6_status_t ninlil_n6_bind_storage(
    ninlil_n6_t *n6, const ninlil_storage_ops_t *ops);

ninlil_n6_status_t ninlil_n6_bind_crypto(
    ninlil_n6_t *n6, const ninlil_n6_crypto_ops_t *ops);

/*
 * Production: fail-closed without R2 accepted-token verifier (not implemented).
 * Test-build unit may accept fixture stamps; not in production archive.
 */
ninlil_n6_status_t ninlil_n6_bind_authority_stamp(
    ninlil_n6_t *n6, const ninlil_n6_authority_stamp_t *stamp);

/*
 * Sole local-identity binder (docs/30 §20.4.1). One-shot consume; INIT+unbound only.
 * BOUND iff storage && crypto && local_identity. Identity required for empty boot.
 */
ninlil_n6_status_t ninlil_n6_bind_local_identity_accepted(
    ninlil_n6_t *n6,
    const ninlil_n6_local_identity_ops_t *ops,
    ninlil_n6_accepted_local_identity_token_t *mutable_token);

/*
 * RO durable full scan + invariant check.
 * Preflight: !storage||!crypto → INVALID_STATE I/O0; !identity → M4_REQUIRED/LOCAL_IDENTITY I/O0.
 * Empty success → BOOTED. Valid durable without RAM secret → DORMANT.
 * HW join uses authenticated local identity + exact scope_digest28.
 */
ninlil_n6_status_t ninlil_n6_boot_scan(ninlil_n6_t *n6);

/*
 * Durable install engine (production-compiled).
 * M4 without adapter → M4_REQUIRED. FIXTURE_ONLY only under NINLIL_N6_TEST_BUILD
 * with bound local identity matching capsule.local_node_id.
 */
ninlil_n6_status_t ninlil_n6_install_hop(
    ninlil_n6_t *n6,
    const ninlil_n6_install_capsule_t *capsule,
    ninlil_n6_handle_t *out_handle);

ninlil_n6_status_t ninlil_n6_install_e2e(
    ninlil_n6_t *n6,
    const ninlil_n6_install_capsule_t *capsule,
    ninlil_n6_handle_t *out_handle);

/*
 * Internal CU classify from copy-owned plan + re-read storage.
 * No external classification input. NEED_CLOSE_OLD→OPEN→READ_CLASSIFY.
 */
ninlil_n6_status_t ninlil_n6_recover_cu(ninlil_n6_t *n6);

/* Durable FULL block reservation then publish lease materials. */
ninlil_n6_status_t ninlil_n6_tx_burn(
    ninlil_n6_t *n6,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    ninlil_n6_tx_lease_t *out_lease);

/* Single-use release; secure-zeros lease materials. */
ninlil_n6_status_t ninlil_n6_tx_lease_release(
    ninlil_n6_t *n6, ninlil_n6_tx_lease_t *lease);

/* Mutation 0; returns AEAD-open ticket materials. */
ninlil_n6_status_t ninlil_n6_rx_precheck(
    ninlil_n6_t *n6,
    ninlil_n6_handle_t handle,
    uint8_t lane_kind,
    uint64_t counter,
    ninlil_n6_rx_ticket_t *out_ticket);

/* Durable FULL admit after AEAD success; zeros ticket. */
ninlil_n6_status_t ninlil_n6_rx_admit_after_aead(
    ninlil_n6_t *n6, ninlil_n6_rx_ticket_t *ticket);

/* Zeroize ticket; no durable mutation. */
ninlil_n6_status_t ninlil_n6_rx_abort(
    ninlil_n6_t *n6, ninlil_n6_rx_ticket_t *ticket);

/*
 * Admin ops: production path fail-closed M4_REQUIRED (no callable success).
 * Durable FULL implementations are not exposed without M4/M5 adapter.
 */
ninlil_n6_status_t ninlil_n6_fence(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle, uint8_t reason);

ninlil_n6_status_t ninlil_n6_restamp(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle);

ninlil_n6_status_t ninlil_n6_reclaim(
    ninlil_n6_t *n6, ninlil_n6_handle_t handle);

ninlil_n6_status_t ninlil_n6_gc(ninlil_n6_t *n6);

ninlil_n6_status_t ninlil_n6_stats(
    const ninlil_n6_t *n6, ninlil_n6_stats_t *out_stats);

ninlil_n6_status_t ninlil_n6_last_error(
    const ninlil_n6_t *n6, ninlil_n6_error_t *out_error);

ninlil_n6_status_t ninlil_n6_shutdown(ninlil_n6_t *n6);

int ninlil_n6_esp_ready(void);

ninlil_n6_state_t ninlil_n6_state(const ninlil_n6_t *n6);

#if defined(NINLIL_N6_TEST_BUILD)
/* Test-only inspection (compiled only into NINLIL_N6_TEST_BUILD store). */
void ninlil_n6_test_paint_boot_scratch(ninlil_n6_t *n6, uint8_t byte);
int ninlil_n6_test_boot_scratch_is_zero(const ninlil_n6_t *n6);
uint8_t ninlil_n6_test_cu_phase(const ninlil_n6_t *n6);
int ninlil_n6_test_cu_live(const ninlil_n6_t *n6);
uint32_t ninlil_n6_test_live_ticket_count(const ninlil_n6_t *n6);
int ninlil_n6_test_any_ticket_key_or_iv_nonzero(const ninlil_n6_t *n6);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_N6_CONTEXT_STORE_H */
