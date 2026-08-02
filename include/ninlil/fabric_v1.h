/*
 * Ninlil portable Fabric v1 public composition API.
 *
 * This experimental 0.x surface is fixed by ADR-0029.  Applications normally
 * use the Foundation Runtime; platform packet-link ports use this API to
 * compose transport without importing implementation headers.
 */
#ifndef NINLIL_FABRIC_V1_H
#define NINLIL_FABRIC_V1_H

#include "ninlil/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_FABRIC_API_VERSION ((uint16_t)0x0001u)
#define NINLIL_FABRIC_PROFILE_1 ((uint32_t)1u)
#define NINLIL_FABRIC_WORKSPACE_BYTES ((uint32_t)198656u)
#define NINLIL_FABRIC_REGISTRY_MAX ((uint32_t)16u)
#define NINLIL_FABRIC_POLICY_MAX ((uint32_t)64u)
#define NINLIL_FABRIC_AUTHORITY_MAX ((uint32_t)64u)
#define NINLIL_FABRIC_ATTEMPT_MAX ((uint32_t)64u)
#define NINLIL_FABRIC_POLICY_CANDIDATES_MAX ((uint32_t)8u)

typedef struct ninlil_fabric_v1 ninlil_fabric_v1_t;
typedef struct ninlil_fabric_link_registration_v1
    ninlil_fabric_link_registration_v1_t;
typedef void *ninlil_fabric_packet_link_handle_t;
typedef void *ninlil_fabric_packet_token_t;

typedef uint32_t ninlil_fabric_status_t;
#define NINLIL_FABRIC_OK 0u
#define NINLIL_FABRIC_INVALID_ARGUMENT 1u
#define NINLIL_FABRIC_WRONG_THREAD 2u
#define NINLIL_FABRIC_REENTRANT 3u
#define NINLIL_FABRIC_CLOSED 4u
#define NINLIL_FABRIC_CONFLICT 5u
#define NINLIL_FABRIC_UNSUPPORTED 6u
#define NINLIL_FABRIC_CORRUPT 7u
#define NINLIL_FABRIC_COMMIT_UNKNOWN 8u
#define NINLIL_FABRIC_DENIED 9u
#define NINLIL_FABRIC_UNAVAILABLE 10u
#define NINLIL_FABRIC_CAPACITY 11u
#define NINLIL_FABRIC_WOULD_BLOCK 12u

typedef uint32_t ninlil_fabric_link_status_t;
#define NINLIL_FABRIC_LINK_OK 0u
#define NINLIL_FABRIC_LINK_EMPTY 1u
#define NINLIL_FABRIC_LINK_RETAINED 2u
#define NINLIL_FABRIC_LINK_WOULD_BLOCK 3u
#define NINLIL_FABRIC_LINK_UNAVAILABLE 4u
#define NINLIL_FABRIC_LINK_DENIED 5u
#define NINLIL_FABRIC_LINK_LOST_UNKNOWN 6u
#define NINLIL_FABRIC_LINK_CORRUPT 7u

typedef uint32_t ninlil_fabric_link_completion_kind_t;
#define NINLIL_FABRIC_LINK_COMPLETION_PENDING 1u
#define NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE 2u
#define NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE 3u
#define NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN 4u

#define NINLIL_FABRIC_LINK_KIND_LOOPBACK 1u
#define NINLIL_FABRIC_LINK_KIND_WIFI 2u
#define NINLIL_FABRIC_LINK_KIND_USB 3u
#define NINLIL_FABRIC_LINK_KIND_RF 4u

#define NINLIL_FABRIC_LINK_DIRECTION_SEND (1u << 0)
#define NINLIL_FABRIC_LINK_DIRECTION_RECEIVE (1u << 1)

#define NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE (1u << 0)
#define NINLIL_FABRIC_CAP_UNICAST (1u << 1)
#define NINLIL_FABRIC_CAP_BROADCAST (1u << 2)
#define NINLIL_FABRIC_CAP_RESERVATION (1u << 3)
#define NINLIL_FABRIC_CAP_REGULATED_RF (1u << 4)
#define NINLIL_FABRIC_CAP_CUSTODY (1u << 5)
#define NINLIL_FABRIC_CAP_EVIDENCE (1u << 6)

#define NINLIL_FABRIC_SECURITY_INTEGRITY (1u << 0)
#define NINLIL_FABRIC_SECURITY_CONFIDENTIALITY (1u << 1)
#define NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION (1u << 2)
#define NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS (1u << 3)

#define NINLIL_FABRIC_PEER_CAP_NFL1_V1 (1u << 0)

#define NINLIL_FABRIC_POLICY_DIRECTION_FORWARD 1u
#define NINLIL_FABRIC_POLICY_DIRECTION_REVERSE 2u
#define NINLIL_FABRIC_TRAFFIC_APPLICATION 1u
#define NINLIL_FABRIC_TRAFFIC_CONTROL 2u

#define NINLIL_FABRIC_AUTHORITY_ABSENT 0u
#define NINLIL_FABRIC_AUTHORITY_BOUND 1u
#define NINLIL_FABRIC_AUTHORITY_MODE_ABSENT_ALLOWED 0u
#define NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED 1u
#define NINLIL_FABRIC_SCOPE_SOURCE_RUNTIME 1u
#define NINLIL_FABRIC_SCOPE_TARGET_RUNTIME 2u

typedef struct ninlil_fabric_config_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t profile_id;
    uint32_t flags;
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;
} ninlil_fabric_config_v1_t;

typedef struct ninlil_fabric_link_descriptor_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_id128_t instance_id;
    uint32_t link_kind;
    uint32_t direction_mask;
    uint32_t capability_flags;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[32];
    ninlil_id128_t security_profile_id;
    uint32_t security_capability_flags;
    uint8_t security_binding_digest[32];
    uint64_t attestation_epoch;
    ninlil_id128_t attestation_clock_epoch_id;
    uint64_t attestation_expires_at_ms;
    uint8_t attestation_digest[32];
    ninlil_id128_t authenticated_peer_runtime_id;
    ninlil_id128_t attachment_authority_id;
    uint8_t attachment_binding_digest[32];
    uint32_t maximum_packet_bytes;
    uint32_t maximum_transfer_bytes;
    uint16_t latency_class;
    uint16_t cost_class;
    uint16_t reservation_capacity;
    uint16_t reserved_zero_u16;
    uint16_t peer_nfl1_version;
    uint16_t reserved_zero_peer_u16;
    uint32_t peer_fabric_capability_flags;
    uint64_t configuration_revision;
    uint8_t configuration_digest[32];
} ninlil_fabric_link_descriptor_v1_t;

typedef struct ninlil_fabric_policy_candidate_v1 {
    ninlil_id128_t instance_id;
    uint16_t rank;
    uint16_t flags;
    uint16_t reservation_units;
    uint16_t reserved_zero;
} ninlil_fabric_policy_candidate_v1_t;

typedef struct ninlil_fabric_path_policy_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_id128_t policy_id;
    uint64_t revision;
    uint8_t canonical_digest_zero_on_input[32];
    uint8_t service_identity_digest[32];
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint16_t scope_selector;
    uint32_t required_capability_flags;
    uint32_t required_security_flags;
    uint16_t maximum_latency_class;
    uint16_t maximum_cost_class;
    uint32_t minimum_packet_bytes;
    uint8_t authority_mode;
    uint8_t reserved_zero_u8[3];
    uint64_t deadline_guard_ms;
    uint16_t candidate_count;
    uint16_t reserved_zero_u16;
    uint32_t reserved_zero_u32;
    ninlil_fabric_policy_candidate_v1_t candidates[8];
} ninlil_fabric_path_policy_v1_t;

typedef struct ninlil_fabric_authority_binding_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    ninlil_id128_t binding_id;
    uint8_t service_identity_digest[32];
    uint32_t family;
    uint32_t direction;
    uint16_t traffic_class;
    uint16_t scope_selector;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t target_application_id;
    ninlil_id128_t policy_id;
    uint64_t policy_revision;
    uint8_t policy_digest[32];
    uint32_t authority_state;
    ninlil_id128_t authority_id;
    uint64_t authority_term;
    uint32_t assignment_epoch;
    uint32_t reserved_zero_u32;
    ninlil_id128_t owner_scope_id;
    uint8_t owner_tuple_digest[32];
    uint8_t owner_tuple_canonical[200];
    ninlil_id128_t authority_clock_epoch_id;
    uint64_t lease_expires_at_ms;
    uint64_t assignment_revision;
    uint64_t reserved_zero_u64;
} ninlil_fabric_authority_binding_v1_t;

typedef struct ninlil_fabric_link_metrics_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t queued_items;
    uint32_t retained_tokens;
    uint64_t accepted_count;
    uint64_t would_block_count;
    uint64_t unavailable_count;
    uint64_t denied_count;
    uint64_t lost_unknown_count;
    uint64_t corrupt_count;
    uint64_t metrics_revision;
} ninlil_fabric_link_metrics_v1_t;

/*
 * Packet-link provider contract
 * -----------------------------
 * Fabric calls every provider operation synchronously on the execution-owner
 * context captured by create.  A provider must not re-enter Fabric, Runtime,
 * or its own vtable from one of these calls.  The packet view, its bytes, and
 * its TxPermit are borrowed only until start_send returns.
 *
 * RF links require a non-NULL, valid TxPermit.  Before I/O the provider must
 * require permit->abi_version == NINLIL_ABI_VERSION, permit->struct_size ==
 * sizeof(ninlil_tx_permit_t), a non-zero permit_id, and permit->attempt_id ==
 * packet->attempt_id.  Its monotonic Clock now() must return NINLIL_PORT_OK and
 * NINLIL_CLOCK_TRUSTED, with permit->clock_epoch_id == sample.clock_epoch_id,
 * permit->expires_at_ms != 0, and sample.now_ms < permit->expires_at_ms.  On
 * successful acceptance it consumes (clock_epoch_id, permit_id) and must
 * reject every reuse; availability/path selection is never RF permission.
 *
 * open succeeds only as LINK_OK with a non-NULL handle.  start_send has only
 * two valid shapes: LINK_RETAINED with a non-NULL token after the provider has
 * boundedly copy-owned all packet bytes/retry state, or one of WOULD_BLOCK,
 * UNAVAILABLE, DENIED, LOST_UNKNOWN, or CORRUPT with a NULL token.  Fabric
 * polls a retained token at most once per step until terminal, or cancels it
 * exactly once at its deadline.  poll_send is valid only as
 * NINLIL_FABRIC_LINK_OK with completion kind
 * NINLIL_FABRIC_LINK_COMPLETION_PENDING,
 * NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE,
 * NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE, or
 * NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN; cancel_send is valid only as
 * NINLIL_FABRIC_LINK_OK or NINLIL_FABRIC_LINK_LOST_UNKNOWN.  Every other
 * shape is corrupt/unknown-fenced.  Fabric does not poll or cancel again after
 * terminal, then calls release_send exactly once.  The provider must retain
 * the token until then.
 *
 * receive_next returns provider-owned bytes and a non-NULL receive token only
 * with LINK_OK.  Fabric copies the bytes before calling release_received
 * exactly once.  EMPTY/failure returns no bytes/token and receives no release.
 * Provider handle and send/receive tokens remain provider-owned; Fabric never
 * frees them directly.  Every handle from a successful open is passed to
 * close exactly once, after its retained tokens and receive loans are released.
 */
typedef struct ninlil_fabric_packet_view_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    const uint8_t *bytes;
    uint32_t length;
    uint32_t reserved_zero;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t selected_path_id;
    uint64_t path_selection_epoch;
    const ninlil_tx_permit_t *permit;
} ninlil_fabric_packet_view_v1_t;

typedef struct ninlil_fabric_link_completion_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint32_t kind;
    uint32_t reserved_zero;
} ninlil_fabric_link_completion_v1_t;

typedef struct ninlil_fabric_link_state_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    uint64_t availability_epoch;
    ninlil_id128_t availability_clock_epoch_id;
    uint64_t available_until_ms;
    uint32_t available;
    uint32_t reserved_zero;
} ninlil_fabric_link_state_v1_t;

typedef struct ninlil_fabric_packet_link_ops_v1 {
    uint16_t api_version;
    uint16_t struct_size;
    void *user;
    ninlil_fabric_link_status_t (*open)(
        void *user, ninlil_fabric_packet_link_handle_t *out_handle);
    void (*close)(void *user, ninlil_fabric_packet_link_handle_t handle);
    ninlil_fabric_link_status_t (*start_send)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        const ninlil_fabric_packet_view_v1_t *packet,
        ninlil_fabric_packet_token_t *out_token);
    ninlil_fabric_link_status_t (*poll_send)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token,
        ninlil_fabric_link_completion_v1_t *out_completion);
    ninlil_fabric_link_status_t (*cancel_send)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token);
    void (*release_send)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token);
    ninlil_fabric_link_status_t (*receive_next)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        const uint8_t **out_bytes,
        uint32_t *out_length,
        void **out_receive_token);
    void (*release_received)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        void *receive_token);
    ninlil_fabric_link_status_t (*state)(
        void *user,
        ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_link_state_v1_t *out_state);
} ninlil_fabric_packet_link_ops_v1_t;

/*
 * Instance and lifetime contract
 * ------------------------------
 * workspace_required is pure.  create captures a non-zero execution owner;
 * every other operation is owner-context-only.  Calls made from another
 * context return WRONG_THREAD, and calls re-entered from a provider operation
 * return REENTRANT, without storage mutation, provider I/O, or callbacks.
 *
 * The caller owns the workspace from create through successful destroy and
 * must not move, reuse, or free it earlier.  Fabric copies config/link vtables,
 * but their function code and non-NULL user pointees remain caller-owned and
 * valid through destroy, or through completed unregister for a link provider.
 * Registration handles and the returned Bearer ops are Fabric borrows; a
 * registration is consumed when unregister_poll reports done and all remaining
 * Fabric borrows expire at destroy.
 *
 * close_begin starts bounded drain.  Only step advances queued or retained
 * work; close_poll reports done only after all provider tokens/receive loans
 * are released, provider and outer handles are closed, and storage is closed.
 * destroy before that point returns WOULD_BLOCK without consuming the instance;
 * successful destroy consumes the instance and zeroes its workspace region.
 */
ninlil_fabric_status_t ninlil_fabric_v1_workspace_required(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment);
ninlil_fabric_status_t ninlil_fabric_v1_create(
    const ninlil_fabric_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_fabric_v1_t **out_fabric);
ninlil_fabric_status_t ninlil_fabric_v1_bearer_ops(
    ninlil_fabric_v1_t *fabric, const ninlil_bearer_ops_t **out_bearer_ops);
ninlil_fabric_status_t ninlil_fabric_v1_register_link(
    ninlil_fabric_v1_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_link_registration_v1_t **out_registration);
ninlil_fabric_status_t ninlil_fabric_v1_unregister_begin(
    ninlil_fabric_v1_t *fabric,
    ninlil_fabric_link_registration_v1_t *registration);
ninlil_fabric_status_t ninlil_fabric_v1_unregister_poll(
    ninlil_fabric_v1_t *fabric,
    ninlil_fabric_link_registration_v1_t *registration,
    uint32_t *out_done);
ninlil_fabric_status_t ninlil_fabric_v1_policy_put(
    ninlil_fabric_v1_t *fabric, const ninlil_fabric_path_policy_v1_t *policy);
ninlil_fabric_status_t ninlil_fabric_v1_policy_remove(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision);
ninlil_fabric_status_t ninlil_fabric_v1_policy_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision,
    ninlil_fabric_path_policy_v1_t *out_policy);
ninlil_fabric_status_t ninlil_fabric_v1_authority_put(
    ninlil_fabric_v1_t *fabric,
    const ninlil_fabric_authority_binding_v1_t *binding);
ninlil_fabric_status_t ninlil_fabric_v1_authority_remove(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *binding_id,
    uint64_t assignment_revision);
ninlil_fabric_status_t ninlil_fabric_v1_authority_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *binding_id,
    ninlil_fabric_authority_binding_v1_t *out_binding);
ninlil_fabric_status_t ninlil_fabric_v1_link_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state);
ninlil_fabric_status_t ninlil_fabric_v1_link_availability_update(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    const ninlil_fabric_link_state_v1_t *new_state);
ninlil_fabric_status_t ninlil_fabric_v1_metrics_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_metrics_v1_t *out_metrics);
ninlil_fabric_status_t ninlil_fabric_v1_step(
    ninlil_fabric_v1_t *fabric,
    uint32_t work_budget,
    uint32_t *out_work_done);
ninlil_fabric_status_t ninlil_fabric_v1_close_begin(ninlil_fabric_v1_t *fabric);
ninlil_fabric_status_t ninlil_fabric_v1_close_poll(
    ninlil_fabric_v1_t *fabric, uint32_t *out_done);
ninlil_fabric_status_t ninlil_fabric_v1_destroy(ninlil_fabric_v1_t *fabric);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_FABRIC_V1_H */
