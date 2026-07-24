#include "runtime_v1_bearer_wire.h"

#include "runtime_v1_capability.h"
#include "runtime_v1_family_capability.h"
#include "submission_preflight.h"

#include <string.h>

#define NINLIL_RT_V1_MARKER_DS 0x4453u
#define NINLIL_RT_V1_MARKER_EV 0x4556u
#define NINLIL_RT_V1_MARKER_OC 0x4f43u

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static int id_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static void derive_attempt_id(const ninlil_id128_t *txn_id, ninlil_id128_t *attempt_id)
{
    *attempt_id = *txn_id;
    attempt_id->bytes[14] = 0u;
    attempt_id->bytes[15] = 1u;
}

int ninlil_rt_v1_bearer_path_available(ninlil_runtime_t *runtime)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_bearer_state_t state;
    ninlil_bearer_status_t status;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->bearer == NULL || runtime->bearer == NULL) {
        return 0;
    }
    bearer = runtime->platform->bearer;
    if (bearer->state == NULL) {
        return 0;
    }
    (void)memset(&state, 0, sizeof(state));
    set_header(&state.abi_version, &state.struct_size, sizeof(state));
    status = bearer->state(bearer->user, runtime->bearer, &state);
    return status == NINLIL_BEARER_OK && state.available != 0u;
}

static ninlil_rt_service_slot_t *find_downlink_receiver(
    ninlil_runtime_t *runtime,
    ninlil_family_t family)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (slot->descriptor.family != family) {
            continue;
        }
        if (slot->model_service.local_side
            != NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER) {
            continue;
        }
        if (slot->callbacks.on_delivery == NULL) {
            continue;
        }
        return slot;
    }
    return NULL;
}

static ninlil_rt_service_slot_t *find_uplink_receiver(
    ninlil_runtime_t *runtime,
    ninlil_family_t family)
{
    return find_downlink_receiver(runtime, family);
}

static ninlil_rt_service_slot_t *find_uplink_sender(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *txn)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use == 0u || slot->attached == 0u) {
            continue;
        }
        if (slot->descriptor.family != txn->family) {
            continue;
        }
        if (slot->model_service.local_side
            != NINLIL_MODEL_LOCAL_SUBMISSION_SENDER) {
            continue;
        }
        if (memcmp(
                slot->descriptor.local_application_instance_id.bytes,
                txn->service_app_id.bytes,
                sizeof(txn->service_app_id.bytes))
            != 0) {
            continue;
        }
        return slot;
    }
    return NULL;
}

static ninlil_status_t complete_receipt_for_txn(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    if (txn->evidence_recorded != 0u) {
        return NINLIL_OK;
    }
    if (txn->delivery_phase == NINLIL_RT_DELIVERY_NONE) {
        txn->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    }
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
        2u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->evidence_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    out_result->transitions_consumed += 1u;
    txn->outcome = NINLIL_OUTCOME_SATISFIED;
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_OC,
        NINLIL_V1_DURABLE_OP_DELIVERY_OUTCOME_COMMIT,
        3u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->outcome_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
    txn->terminal = 1u;
    txn->pending_dispatch = 0u;
    runtime->nonterminal_transaction_count -= 1u;
    out_result->transitions_consumed += 1u;
    return ninlil_rt_v1_release_transaction_reservation(runtime, txn);
}

static ninlil_status_t send_application_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample);

static ninlil_rt_transaction_slot_t *find_or_alloc_txn(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id)
{
    ninlil_rt_transaction_slot_t *slot;

    slot = ninlil_rt_find_transaction(runtime, transaction_id);
    if (slot != NULL) {
        return slot;
    }
    slot = ninlil_rt_alloc_transaction(runtime);
    if (slot == NULL) {
        return NULL;
    }
    runtime->nonterminal_transaction_count += 1u;
    slot->in_use = 1u;
    slot->transaction_id = *transaction_id;
    slot->retry_budget = 3u;
    slot->retry_backoff_ms = 100u;
    slot->spool_revision = 1u;
    return slot;
}

static ninlil_status_t handle_incoming_downlink_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;

    if (runtime->config.role != NINLIL_ROLE_CONTROLLER) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL || !ninlil_rt_v1_family_is_downlink(txn->family)) {
        return NINLIL_OK;
    }
    return complete_receipt_for_txn(runtime, txn, out_result);
}

static ninlil_status_t handle_incoming_uplink_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_OK;
    }
    txn = ninlil_rt_find_transaction(runtime, &message->transaction_id);
    if (txn == NULL || !ninlil_rt_v1_family_is_uplink(txn->family)) {
        return NINLIL_OK;
    }
    return complete_receipt_for_txn(runtime, txn, out_result);
}

static ninlil_status_t handle_incoming_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    status = handle_incoming_downlink_receipt(runtime, message, out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    return handle_incoming_uplink_receipt(runtime, message, out_result);
}

static ninlil_status_t handle_incoming_downlink_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_family_t wire_family = NINLIL_FAMILY_DESIRED_STATE;
    ninlil_rt_service_slot_t *receiver;
    ninlil_rt_transaction_slot_t *txn;
    ninlil_delivery_token_t token;
    ninlil_delivery_view_t delivery_view;
    ninlil_application_result_t app_result;
    ninlil_callback_action_t action;
    ninlil_status_t status;

    if (runtime->config.role != NINLIL_ROLE_ENDPOINT) {
        return NINLIL_OK;
    }
    if (message->kind != NINLIL_BEARER_MESSAGE_APPLICATION) {
        return NINLIL_OK;
    }
    wire_family = message->service.family;
    if (!ninlil_rt_v1_family_is_downlink(wire_family)) {
        return NINLIL_OK;
    }
    receiver = find_downlink_receiver(runtime, wire_family);
    if (receiver == NULL) {
        return NINLIL_OK;
    }
    txn = find_or_alloc_txn(runtime, &message->transaction_id);
    if (txn == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    txn->family = wire_family;
    txn->service_app_id = receiver->descriptor.local_application_instance_id;
    txn->content_digest = message->content_digest;
    txn->generation = message->generation;
    txn->effect_deadline_ms = message->absolute_effect_deadline_ms;
    txn->payload_length = (uint32_t)message->payload.length;
    txn->pending_dispatch = 0u;

    if (txn->evidence_recorded != 0u) {
        /* Dedup: evidence already durable — skip callback, still ACK. */
    } else if (callback_budget == 0u) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    } else {
        (void)memset(&token, 0, sizeof(token));
        set_header(&token.abi_version, &token.struct_size, sizeof(token));
        token.context_id = runtime->config.runtime_id;
        token.clock_epoch_id = clock_sample->clock_epoch_id;
        token.generation = 1u;
        token.expires_at_ms = message->absolute_effect_deadline_ms;
        (void)memset(&delivery_view, 0, sizeof(delivery_view));
        set_header(
            &delivery_view.abi_version,
            &delivery_view.struct_size,
            sizeof(delivery_view));
        delivery_view.transaction_id = message->transaction_id;
        delivery_view.content_digest = message->content_digest;
        delivery_view.generation = message->generation;
        delivery_view.delivery_count = 1u;
        delivery_view.required_evidence = NINLIL_EVIDENCE_APPLIED;
        delivery_view.deadline_clock_epoch_id = clock_sample->clock_epoch_id;
        delivery_view.absolute_effect_deadline_ms = message->absolute_effect_deadline_ms;
        (void)memset(&app_result, 0, sizeof(app_result));
        set_header(&app_result.abi_version, &app_result.struct_size, sizeof(app_result));
        if (wire_family == NINLIL_FAMILY_TRANSFER_RESERVED) {
            ninlil_rt_v1_family_workspace_t *ws =
                ninlil_rt_v1_family_workspace(runtime);
            if (!ninlil_rt_v1_family_bounded_transfer_begin(
                    ws,
                    &message->transaction_id,
                    (uint32_t)message->generation)) {
                return NINLIL_OK;
            }
            if (!ninlil_rt_v1_family_bounded_transfer_receive(
                    ws,
                    &message->transaction_id,
                    (uint32_t)message->payload.length,
                    1)) {
                (void)ninlil_rt_v1_family_bounded_transfer_abort(
                    ws, &message->transaction_id);
                return NINLIL_OK;
            }
            if (!ninlil_rt_v1_family_bounded_transfer_may_apply(
                    ws, &message->transaction_id)) {
                return NINLIL_OK;
            }
        } else if (wire_family == NINLIL_FAMILY_CONFIG_RESERVED) {
            uint8_t stage = NINLIL_RT_V1_CONFIG_STAGE_STAGED;
            if (message->payload.length > 0u && message->payload.data != NULL) {
                stage = message->payload.data[0];
            }
            if (!ninlil_rt_v1_family_config_revision_advance(
                    ninlil_rt_v1_family_workspace(runtime),
                    &receiver->descriptor.local_application_instance_id,
                    message->generation,
                    stage,
                    &app_result)) {
                if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                    return NINLIL_OK;
                }
                (void)ninlil_rt_v1_family_config_revision_rollback(
                    ninlil_rt_v1_family_workspace(runtime),
                    &receiver->descriptor.local_application_instance_id);
                return NINLIL_OK;
            }
        }
        runtime->in_callback = 1u;
        action = receiver->callbacks.on_delivery(
            receiver->callbacks.user,
            &token,
            &delivery_view,
            &app_result);
        runtime->in_callback = 0u;
        out_result->callbacks_invoked += 1u;
        if (action != NINLIL_CALLBACK_COMPLETE
            || app_result.kind != NINLIL_APP_RESULT_POSITIVE_EVIDENCE) {
            return NINLIL_OK;
        }
        status = ninlil_rt_v1_commit_delivery_marker(
            runtime,
            txn,
            NINLIL_RT_V1_MARKER_EV,
            NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
            2u);
        if (status != NINLIL_OK) {
            return status;
        }
        txn->evidence_recorded = 1u;
        txn->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
        out_result->transitions_consumed += 1u;
    }

    return send_application_receipt(runtime, message, clock_sample);
}

static ninlil_status_t send_application_receipt(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample)
{
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t receipt;
    ninlil_bearer_send_result_t send_result;
    ninlil_id128_t attempt_id;

    bearer = runtime->platform->bearer;
    tx_gate = runtime->platform->tx_gate;
    if (bearer == NULL || tx_gate == NULL || runtime->bearer == NULL) {
        return NINLIL_OK;
    }
    derive_attempt_id(&message->transaction_id, &attempt_id);
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = message->transaction_id;
    tx_request.attempt_id = attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    tx_request.logical_bytes = 64u;
    tx_request.content_digest = message->content_digest;
    if (tx_gate->acquire(tx_gate->user, &tx_request, clock_sample, &permit)
        != NINLIL_TX_GATE_OK) {
        return NINLIL_OK;
    }
    (void)memset(&receipt, 0, sizeof(receipt));
    set_header(&receipt.abi_version, &receipt.struct_size, sizeof(receipt));
    receipt.kind = NINLIL_BEARER_MESSAGE_RECEIPT;
    receipt.transaction_id = message->transaction_id;
    receipt.attempt_id = attempt_id;
    receipt.content_digest = message->content_digest;
    receipt.receipt_stage = NINLIL_EVIDENCE_APPLIED;
    receipt.evidence_time = *clock_sample;
    (void)memset(&send_result, 0, sizeof(send_result));
    set_header(&send_result.abi_version, &send_result.struct_size, sizeof(send_result));
    if (bearer->send(
            bearer->user,
            runtime->bearer,
            &permit,
            &receipt,
            &send_result)
        == NINLIL_BEARER_OK) {
        tx_gate->release_unused(tx_gate->user, &permit);
    }
    return NINLIL_OK;
}

static ninlil_status_t handle_incoming_uplink_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_family_t wire_family;
    ninlil_rt_service_slot_t *receiver;
    ninlil_rt_transaction_slot_t *txn;
    ninlil_delivery_token_t token;
    ninlil_delivery_view_t delivery_view;
    ninlil_application_result_t app_result;
    ninlil_callback_action_t action;
    ninlil_status_t status;

    if (runtime->config.role != NINLIL_ROLE_CONTROLLER
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION) {
        return NINLIL_OK;
    }
    wire_family = message->service.family;
    if (!ninlil_rt_v1_family_is_uplink(wire_family)) {
        return NINLIL_OK;
    }
    receiver = find_uplink_receiver(runtime, wire_family);
    if (receiver == NULL) {
        return NINLIL_OK;
    }
    txn = find_or_alloc_txn(runtime, &message->transaction_id);
    if (txn == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    txn->family = wire_family;
    txn->service_app_id = receiver->descriptor.local_application_instance_id;
    txn->content_digest = message->content_digest;
    txn->generation = message->generation;
    txn->effect_deadline_ms = message->absolute_effect_deadline_ms;
    txn->payload_length = (uint32_t)message->payload.length;
    txn->pending_dispatch = 0u;

    if (txn->evidence_recorded != 0u) {
        return send_application_receipt(runtime, message, clock_sample);
    }
    if (callback_budget == 0u) {
        out_result->work_remaining = 1u;
        return NINLIL_OK;
    }
    (void)memset(&token, 0, sizeof(token));
    set_header(&token.abi_version, &token.struct_size, sizeof(token));
    token.context_id = runtime->config.runtime_id;
    token.clock_epoch_id = clock_sample->clock_epoch_id;
    token.generation = message->generation;
    token.expires_at_ms = message->absolute_effect_deadline_ms;
    (void)memset(&delivery_view, 0, sizeof(delivery_view));
    set_header(
        &delivery_view.abi_version,
        &delivery_view.struct_size,
        sizeof(delivery_view));
    delivery_view.transaction_id = message->transaction_id;
    delivery_view.content_digest = message->content_digest;
    delivery_view.generation = message->generation;
    delivery_view.delivery_count = 1u;
    delivery_view.required_evidence = NINLIL_EVIDENCE_APPLIED;
    delivery_view.deadline_clock_epoch_id = clock_sample->clock_epoch_id;
    delivery_view.absolute_effect_deadline_ms = message->absolute_effect_deadline_ms;
    (void)memset(&app_result, 0, sizeof(app_result));
    set_header(&app_result.abi_version, &app_result.struct_size, sizeof(app_result));
    if (wire_family == NINLIL_FAMILY_LATEST_STATE_RESERVED) {
        if (!ninlil_rt_v1_family_latest_state_apply(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                message->generation,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    } else if (wire_family == NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        if (!ninlil_rt_v1_family_measurement_batch_accept(
                ninlil_rt_v1_family_workspace(runtime),
                &receiver->descriptor.local_application_instance_id,
                message->generation,
                (uint32_t)message->payload.length,
                &app_result)) {
            if (app_result.kind == NINLIL_APP_RESULT_DISPOSITION) {
                return NINLIL_OK;
            }
            return NINLIL_E_INVALID_STATE;
        }
    }
    runtime->in_callback = 1u;
    action = receiver->callbacks.on_delivery(
        receiver->callbacks.user,
        &token,
        &delivery_view,
        &app_result);
    runtime->in_callback = 0u;
    out_result->callbacks_invoked += 1u;
    if (action != NINLIL_CALLBACK_COMPLETE
        || app_result.kind != NINLIL_APP_RESULT_POSITIVE_EVIDENCE) {
        return NINLIL_OK;
    }
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_EV,
        NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
        2u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->evidence_recorded = 1u;
    txn->delivery_phase = NINLIL_RT_DELIVERY_EVIDENCED;
    out_result->transitions_consumed += 1u;
    return send_application_receipt(runtime, message, clock_sample);
}

static ninlil_status_t handle_incoming_application(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *clock_sample,
    uint32_t callback_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    ninlil_status_t status;

    status = handle_incoming_downlink_application(
        runtime, message, clock_sample, callback_budget, out_result);
    if (status != NINLIL_OK) {
        return status;
    }
    return handle_incoming_uplink_application(
        runtime, message, clock_sample, callback_budget, out_result);
}

ninlil_status_t ninlil_rt_v1_bearer_ingress_step(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *clock_sample,
    uint32_t *inout_ingress_budget,
    uint32_t callback_budget,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    ninlil_bearer_message_t message;
    ninlil_bearer_status_t status;
    ninlil_status_t result = NINLIL_OK;

    if (!ninlil_rt_v1_bearer_path_available(runtime)) {
        return NINLIL_OK;
    }
    if (inout_ingress_budget == NULL || *inout_ingress_budget == 0u) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    for (;;) {
        if (*inout_ingress_budget == 0u) {
            break;
        }
        (void)memset(&message, 0, sizeof(message));
        set_header(&message.abi_version, &message.struct_size, sizeof(message));
        status = bearer->receive_next(bearer->user, runtime->bearer, &message);
        if (status == NINLIL_BEARER_EMPTY) {
            break;
        }
        if (status != NINLIL_BEARER_OK) {
            break;
        }
        *inout_ingress_budget -= 1u;
        if (message.kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
            result = handle_incoming_receipt(runtime, &message, out_result);
        } else if (message.kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
            result = handle_incoming_application(
                runtime, &message, clock_sample, callback_budget, out_result);
        }
        bearer->release_received(bearer->user, runtime->bearer, &message);
        if (result != NINLIL_OK) {
            return result;
        }
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_bearer_send_desired_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t message;
    ninlil_bearer_send_result_t send_result;
    ninlil_id128_t attempt_id;
    ninlil_status_t status;
    uint32_t index;
    ninlil_rt_service_slot_t *sender = NULL;

    if (!ninlil_rt_v1_bearer_path_available(runtime)
        || runtime->config.role != NINLIL_ROLE_CONTROLLER
        || !ninlil_rt_v1_family_is_downlink(txn->family)) {
        return NINLIL_OK;
    }
    if (txn->delivery_phase != NINLIL_RT_DELIVERY_NONE
        && txn->delivery_phase != NINLIL_RT_DELIVERY_QUEUED) {
        return NINLIL_OK;
    }
    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];
        if (slot->in_use != 0u && slot->attached != 0u
            && slot->descriptor.family == txn->family
            && slot->model_service.local_side
                == NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
            && id_nonzero(&slot->descriptor.local_application_instance_id)
            && memcmp(
                slot->descriptor.local_application_instance_id.bytes,
                txn->service_app_id.bytes,
                sizeof(txn->service_app_id.bytes))
                == 0) {
            sender = slot;
            break;
        }
    }
    if (sender == NULL) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    tx_gate = runtime->platform->tx_gate;
    derive_attempt_id(&txn->transaction_id, &attempt_id);
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = txn->transaction_id;
    tx_request.attempt_id = attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    tx_request.logical_bytes = 64u + txn->payload_length;
    tx_request.content_digest = txn->content_digest;
    if (tx_gate->acquire(tx_gate->user, &tx_request, clock_sample, &permit)
        != NINLIL_TX_GATE_OK) {
        return NINLIL_OK;
    }
    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.transaction_id = txn->transaction_id;
    message.attempt_id = attempt_id;
    message.content_digest = txn->content_digest;
    message.generation = txn->generation;
    message.absolute_effect_deadline_ms = txn->effect_deadline_ms;
    message.required_evidence = NINLIL_EVIDENCE_APPLIED;
    message.service = sender->model_service.identity;
    message.source = sender->model_service.source;
    if (bearer->send(
            bearer->user,
            runtime->bearer,
            &permit,
            &message,
            &send_result)
        != NINLIL_BEARER_OK) {
        tx_gate->release_unused(tx_gate->user, &permit);
        return NINLIL_OK;
    }
    tx_gate->release_unused(tx_gate->user, &permit);
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_DS,
        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
        1u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    txn->delivery_count = 1u;
    txn->pending_dispatch = 0u;
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_bearer_send_uplink_application(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *txn,
    const ninlil_time_sample_t *clock_sample,
    ninlil_rt_v1_step_delivery_result_t *out_result)
{
    const ninlil_bearer_ops_t *bearer;
    const ninlil_tx_gate_ops_t *tx_gate;
    ninlil_tx_request_t tx_request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_message_t message;
    ninlil_bearer_send_result_t send_result;
    ninlil_id128_t attempt_id;
    ninlil_status_t status;
    ninlil_rt_service_slot_t *sender;

    if (!ninlil_rt_v1_bearer_path_available(runtime)
        || runtime->config.role != NINLIL_ROLE_ENDPOINT
        || !ninlil_rt_v1_family_is_uplink(txn->family)) {
        return NINLIL_OK;
    }
    if (txn->delivery_phase != NINLIL_RT_DELIVERY_NONE
        && txn->delivery_phase != NINLIL_RT_DELIVERY_QUEUED) {
        return NINLIL_OK;
    }
    sender = find_uplink_sender(runtime, txn);
    if (sender == NULL) {
        return NINLIL_OK;
    }
    bearer = runtime->platform->bearer;
    tx_gate = runtime->platform->tx_gate;
    derive_attempt_id(&txn->transaction_id, &attempt_id);
    (void)memset(&tx_request, 0, sizeof(tx_request));
    set_header(&tx_request.abi_version, &tx_request.struct_size, sizeof(tx_request));
    tx_request.transaction_id = txn->transaction_id;
    tx_request.attempt_id = attempt_id;
    tx_request.message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    tx_request.logical_bytes = 64u + txn->payload_length;
    tx_request.content_digest = txn->content_digest;
    if (tx_gate->acquire(tx_gate->user, &tx_request, clock_sample, &permit)
        != NINLIL_TX_GATE_OK) {
        return NINLIL_OK;
    }
    (void)memset(&message, 0, sizeof(message));
    set_header(&message.abi_version, &message.struct_size, sizeof(message));
    message.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    message.transaction_id = txn->transaction_id;
    message.attempt_id = attempt_id;
    message.content_digest = txn->content_digest;
    message.generation = txn->generation;
    message.absolute_effect_deadline_ms = txn->effect_deadline_ms;
    message.required_evidence = NINLIL_EVIDENCE_APPLIED;
    message.service = sender->model_service.identity;
    message.source = sender->model_service.source;
    if (bearer->send(
            bearer->user,
            runtime->bearer,
            &permit,
            &message,
            &send_result)
        != NINLIL_BEARER_OK) {
        tx_gate->release_unused(tx_gate->user, &permit);
        return NINLIL_OK;
    }
    tx_gate->release_unused(tx_gate->user, &permit);
    status = ninlil_rt_v1_commit_delivery_marker(
        runtime,
        txn,
        NINLIL_RT_V1_MARKER_DS,
        NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
        1u);
    if (status != NINLIL_OK) {
        return status;
    }
    txn->delivery_phase = NINLIL_RT_DELIVERY_STARTED;
    txn->delivery_count = 1u;
    txn->pending_dispatch = 0u;
    out_result->transitions_consumed += 1u;
    return NINLIL_OK;
}
