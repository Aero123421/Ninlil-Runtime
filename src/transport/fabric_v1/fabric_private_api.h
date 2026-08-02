/*
 * Fabric v1 implementation API.  Not installed and not public ABI.
 *
 * Public value layouts and closed result catalogs have exactly one source:
 * ninlil/fabric_v1.h.  The aliases below preserve the accepted private
 * candidate symbols while the ADR-0029 public wrapper remains one-to-one.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_API_H
#define NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_API_H

#include "ninlil/fabric_v1.h"

#include "fabric_private_nfl1.h"
#include "fabric_private_records.h"
#include "fabric_private_select.h"
#include "fabric_private_util.h"
#include "fabric_workspace.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ninlil_fabric_v1_t ninlil_fabric_private_t;
typedef ninlil_fabric_link_registration_v1_t
    ninlil_fabric_registration_private_t;
typedef ninlil_fabric_status_t ninlil_fabric_private_status_t;

/* Private composition type; Fabric remains independently buildable. */
struct ninlil_rrmp_owner;

#define NINLIL_FABRIC_PRIVATE_OK NINLIL_FABRIC_OK
#define NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT NINLIL_FABRIC_INVALID_ARGUMENT
#define NINLIL_FABRIC_PRIVATE_WRONG_THREAD NINLIL_FABRIC_WRONG_THREAD
#define NINLIL_FABRIC_PRIVATE_REENTRANT NINLIL_FABRIC_REENTRANT
#define NINLIL_FABRIC_PRIVATE_CLOSED NINLIL_FABRIC_CLOSED
#define NINLIL_FABRIC_PRIVATE_CONFLICT NINLIL_FABRIC_CONFLICT
#define NINLIL_FABRIC_PRIVATE_UNSUPPORTED NINLIL_FABRIC_UNSUPPORTED
#define NINLIL_FABRIC_PRIVATE_CORRUPT NINLIL_FABRIC_CORRUPT
#define NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN NINLIL_FABRIC_COMMIT_UNKNOWN
#define NINLIL_FABRIC_PRIVATE_DENIED NINLIL_FABRIC_DENIED
#define NINLIL_FABRIC_PRIVATE_UNAVAILABLE NINLIL_FABRIC_UNAVAILABLE
#define NINLIL_FABRIC_PRIVATE_CAPACITY NINLIL_FABRIC_CAPACITY
#define NINLIL_FABRIC_PRIVATE_WOULD_BLOCK NINLIL_FABRIC_WOULD_BLOCK

ninlil_fabric_private_status_t ninlil_fabric_private_workspace_required_v1(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment);
ninlil_fabric_private_status_t ninlil_fabric_private_create_v1(
    const ninlil_fabric_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_fabric_private_t **out_fabric);
ninlil_fabric_private_status_t ninlil_fabric_private_bearer_ops_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_bearer_ops_t **out_bearer_ops);
/*
 * Instance-local Fabric -> RRMP composition seam. NULL detaches. Binding a
 * different non-NULL owner requires an explicit detach first.
 */
ninlil_fabric_private_status_t ninlil_fabric_private_bind_rrmp_owner_v1(
    ninlil_fabric_private_t *fabric, struct ninlil_rrmp_owner *owner);
ninlil_fabric_private_status_t ninlil_fabric_private_register_link_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_registration_private_t **out_registration);
ninlil_fabric_private_status_t ninlil_fabric_private_unregister_begin_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration);
ninlil_fabric_private_status_t ninlil_fabric_private_unregister_poll_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration,
    uint32_t *out_done);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_path_policy_v1_t *policy);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision,
    ninlil_fabric_path_policy_v1_t *out_policy);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_authority_binding_v1_t *binding);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id,
    uint64_t assignment_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id,
    ninlil_fabric_authority_binding_v1_t *out_binding);
ninlil_fabric_private_status_t ninlil_fabric_private_link_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state);
ninlil_fabric_private_status_t ninlil_fabric_private_link_availability_update_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    const ninlil_fabric_link_state_v1_t *new_state);
ninlil_fabric_private_status_t ninlil_fabric_private_metrics_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_metrics_v1_t *out_metrics);
ninlil_fabric_private_status_t ninlil_fabric_private_step_v1(
    ninlil_fabric_private_t *fabric,
    uint32_t work_budget,
    uint32_t *out_work_done);
ninlil_fabric_private_status_t ninlil_fabric_private_close_begin_v1(
    ninlil_fabric_private_t *fabric);
ninlil_fabric_private_status_t ninlil_fabric_private_close_poll_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_done);
ninlil_fabric_private_status_t ninlil_fabric_private_destroy_v1(
    ninlil_fabric_private_t *fabric);

/* Private proof/reconciliation/codec seams are intentionally not public. */
uint32_t ninlil_fabric_private_workspace_layout_proof_v1(
    uint32_t *out_total,
    ninlil_fabric_ws_region_info_t out_regions[11]);
uint32_t ninlil_fabric_private_object_partition_proof_v1(
    uint32_t *out_object_bytes,
    uint32_t *out_workspace_bytes,
    ninlil_fabric_ws_region_info_t out_objects[11]);
ninlil_fabric_private_status_t ninlil_fabric_private_dispatch_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *attempt_id,
    uint32_t message_kind,
    uint32_t response_slot,
    const uint8_t foundation_message_digest[32],
    uint64_t runtime_terminal_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_trigger_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *triggering_attempt_id,
    uint32_t triggering_kind,
    uint64_t runtime_terminal_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_terminal_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    uint64_t runtime_terminal_revision,
    uint32_t *out_work_done,
    uint32_t *out_more);
/* RAM-only composition queries; neither calls a provider or Storage. */
ninlil_fabric_private_status_t
ninlil_fabric_private_has_link_registrations_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_present);
ninlil_fabric_private_status_t ninlil_fabric_private_has_pending_work_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_present);
ninlil_fabric_private_status_t ninlil_fabric_private_enrich_nfl1_v1(
    const ninlil_bearer_message_t *message,
    const uint8_t authority_id[16],
    uint64_t authority_term,
    uint32_t assignment_epoch,
    const uint8_t route_policy_id[16],
    uint64_t route_policy_revision,
    const uint8_t route_policy_digest[32],
    const uint8_t selected_path_id[16],
    uint64_t path_selection_epoch,
    uint8_t *out_packet,
    uint32_t out_capacity,
    uint32_t *out_length);
ninlil_fabric_private_status_t ninlil_fabric_private_project_bearer_v1(
    const uint8_t *packet,
    uint32_t packet_length,
    ninlil_fabric_private_nfl1_workspace_t *workspace,
    ninlil_bearer_message_t *out_message);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_FABRIC_PRIVATE_API_H */
