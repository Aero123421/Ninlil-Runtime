#include "ninlil/fabric_v1.h"

#include "fabric_private_api.h"

ninlil_fabric_status_t ninlil_fabric_v1_workspace_required(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment)
{
    return ninlil_fabric_private_workspace_required_v1(
        profile_id, out_bytes, out_alignment);
}

ninlil_fabric_status_t ninlil_fabric_v1_create(
    const ninlil_fabric_config_v1_t *config,
    void *workspace,
    uint32_t workspace_bytes,
    ninlil_fabric_v1_t **out_fabric)
{
    return ninlil_fabric_private_create_v1(
        config, workspace, workspace_bytes, out_fabric);
}

ninlil_fabric_status_t ninlil_fabric_v1_bearer_ops(
    ninlil_fabric_v1_t *fabric, const ninlil_bearer_ops_t **out_bearer_ops)
{
    return ninlil_fabric_private_bearer_ops_v1(fabric, out_bearer_ops);
}

ninlil_fabric_status_t ninlil_fabric_v1_register_link(
    ninlil_fabric_v1_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_link_registration_v1_t **out_registration)
{
    return ninlil_fabric_private_register_link_v1(
        fabric, descriptor, ops, out_registration);
}

ninlil_fabric_status_t ninlil_fabric_v1_unregister_begin(
    ninlil_fabric_v1_t *fabric,
    ninlil_fabric_link_registration_v1_t *registration)
{
    return ninlil_fabric_private_unregister_begin_v1(fabric, registration);
}

ninlil_fabric_status_t ninlil_fabric_v1_unregister_poll(
    ninlil_fabric_v1_t *fabric,
    ninlil_fabric_link_registration_v1_t *registration,
    uint32_t *out_done)
{
    return ninlil_fabric_private_unregister_poll_v1(
        fabric, registration, out_done);
}

ninlil_fabric_status_t ninlil_fabric_v1_policy_put(
    ninlil_fabric_v1_t *fabric, const ninlil_fabric_path_policy_v1_t *policy)
{
    return ninlil_fabric_private_policy_put_v1(fabric, policy);
}

ninlil_fabric_status_t ninlil_fabric_v1_policy_remove(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision)
{
    return ninlil_fabric_private_policy_remove_v1(fabric, policy_id, revision);
}

ninlil_fabric_status_t ninlil_fabric_v1_policy_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *policy_id,
    uint64_t revision,
    ninlil_fabric_path_policy_v1_t *out_policy)
{
    return ninlil_fabric_private_policy_snapshot_v1(
        fabric, policy_id, revision, out_policy);
}

ninlil_fabric_status_t ninlil_fabric_v1_authority_put(
    ninlil_fabric_v1_t *fabric,
    const ninlil_fabric_authority_binding_v1_t *binding)
{
    return ninlil_fabric_private_authority_put_v1(fabric, binding);
}

ninlil_fabric_status_t ninlil_fabric_v1_authority_remove(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *binding_id,
    uint64_t assignment_revision)
{
    return ninlil_fabric_private_authority_remove_v1(
        fabric, binding_id, assignment_revision);
}

ninlil_fabric_status_t ninlil_fabric_v1_authority_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *binding_id,
    ninlil_fabric_authority_binding_v1_t *out_binding)
{
    return ninlil_fabric_private_authority_snapshot_v1(
        fabric, binding_id, out_binding);
}

ninlil_fabric_status_t ninlil_fabric_v1_link_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state)
{
    return ninlil_fabric_private_link_snapshot_v1(
        fabric, instance_id, out_descriptor, out_state);
}

ninlil_fabric_status_t ninlil_fabric_v1_link_availability_update(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    const ninlil_fabric_link_state_v1_t *new_state)
{
    return ninlil_fabric_private_link_availability_update_v1(
        fabric, instance_id, new_state);
}

ninlil_fabric_status_t ninlil_fabric_v1_metrics_snapshot(
    ninlil_fabric_v1_t *fabric,
    const ninlil_id128_t *instance_id,
    ninlil_fabric_link_metrics_v1_t *out_metrics)
{
    return ninlil_fabric_private_metrics_snapshot_v1(
        fabric, instance_id, out_metrics);
}

ninlil_fabric_status_t ninlil_fabric_v1_step(
    ninlil_fabric_v1_t *fabric,
    uint32_t work_budget,
    uint32_t *out_work_done)
{
    return ninlil_fabric_private_step_v1(fabric, work_budget, out_work_done);
}

ninlil_fabric_status_t ninlil_fabric_v1_close_begin(ninlil_fabric_v1_t *fabric)
{
    return ninlil_fabric_private_close_begin_v1(fabric);
}

ninlil_fabric_status_t ninlil_fabric_v1_close_poll(
    ninlil_fabric_v1_t *fabric, uint32_t *out_done)
{
    return ninlil_fabric_private_close_poll_v1(fabric, out_done);
}

ninlil_fabric_status_t ninlil_fabric_v1_destroy(ninlil_fabric_v1_t *fabric)
{
    return ninlil_fabric_private_destroy_v1(fabric);
}
