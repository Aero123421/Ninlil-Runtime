#include "ninlil_posix_loopback_bearer_inject.h"

#include <stdlib.h>
#include <string.h>

typedef struct delayed_frame {
    ninlil_bearer_message_t message;
    uint8_t *payload;
    uint8_t *evidence;
    uint8_t *namespace_id;
    uint8_t *service_id;
    uint8_t *schema_id;
    uint32_t deliver_after_steps;
    struct delayed_frame *next;
} delayed_frame_t;

struct ninlil_posix_loopback_bearer_inject {
    ninlil_posix_loopback_bearer_inject_config_t config;
    ninlil_bearer_ops_t bearer_ops;
    ninlil_tx_gate_ops_t tx_gate_ops;
    uint64_t send_seq;
    uint64_t recv_seq;
    uint64_t send_count;
    uint64_t recv_count;
    uint64_t drop_count;
    uint32_t drops_used;
    uint32_t dups_used;
    delayed_frame_t *delayed;
};

static int should_drop_send(
    ninlil_posix_loopback_bearer_inject_t *inject,
    ninlil_bearer_message_kind_t kind)
{
    if (inject->config.mode == NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_DATA
        && kind == NINLIL_BEARER_MESSAGE_APPLICATION
        && inject->drops_used < inject->config.drop_budget) {
        inject->drops_used += 1u;
        inject->drop_count += 1u;
        return 1;
    }
    return 0;
}

static void free_delayed(delayed_frame_t *frame)
{
    if (frame != NULL) {
        free(frame->payload);
        free(frame->evidence);
        free(frame->namespace_id);
        free(frame->service_id);
        free(frame->schema_id);
        free(frame);
    }
}

static ninlil_bearer_status_t inject_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    return inject->config.inner_bearer->open(
        inject->config.inner_user, runtime_id, role, out_handle);
}

static void inject_close(void *user, ninlil_bearer_handle_t handle)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    inject->config.inner_bearer->close(inject->config.inner_user, handle);
}

static ninlil_bearer_status_t inject_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    ninlil_bearer_status_t status;

    if (message == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    inject->send_seq += 1u;
    if (should_drop_send(inject, message->kind)) {
        (void)memset(out_result, 0, sizeof(*out_result));
        out_result->abi_version = NINLIL_ABI_VERSION;
        out_result->struct_size = (uint16_t)sizeof(*out_result);
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    status = inject->config.inner_bearer->send(
        inject->config.inner_user, handle, permit, message, out_result);
    if (status == NINLIL_BEARER_OK) {
        inject->send_count += 1u;
        if (inject->config.mode == NINLIL_POSIX_LOOPBACK_INJECT_MODE_DUPLICATE
            && inject->dups_used < inject->config.duplicate_budget
            && message->kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
            ninlil_tx_request_t dup_req;
            ninlil_tx_permit_t dup_permit;
            ninlil_bearer_send_result_t dup_result;
            ninlil_time_sample_t now;

            (void)memset(&dup_req, 0, sizeof(dup_req));
            dup_req.abi_version = NINLIL_ABI_VERSION;
            dup_req.struct_size = (uint16_t)sizeof(dup_req);
            dup_req.transaction_id = message->transaction_id;
            dup_req.attempt_id = message->attempt_id;
            dup_req.message_kind = message->kind;
            dup_req.logical_bytes = 64u + message->payload.length;
            dup_req.content_digest = message->content_digest;
            (void)memset(&now, 0, sizeof(now));
            now.abi_version = NINLIL_ABI_VERSION;
            now.struct_size = (uint16_t)sizeof(now);
            now.clock_epoch_id = permit->clock_epoch_id;
            now.now_ms = 1000u;
            now.trust = NINLIL_CLOCK_TRUSTED;
            if (inject->config.inner_tx_gate->acquire(
                    inject->config.inner_user, &dup_req, &now, &dup_permit)
                == NINLIL_TX_GATE_OK) {
                (void)memset(&dup_result, 0, sizeof(dup_result));
                dup_result.abi_version = NINLIL_ABI_VERSION;
                dup_result.struct_size = (uint16_t)sizeof(dup_result);
                if (inject->config.inner_bearer->send(
                        inject->config.inner_user,
                        handle,
                        &dup_permit,
                        message,
                        &dup_result)
                    == NINLIL_BEARER_OK) {
                    inject->send_count += 1u;
                }
                inject->config.inner_tx_gate->release_unused(
                    inject->config.inner_user, &dup_permit);
                inject->dups_used += 1u;
            }
        }
    }
    return status;
}

static ninlil_bearer_status_t inject_receive(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    ninlil_bearer_status_t status;

    inject->recv_seq += 1u;
    status = inject->config.inner_bearer->receive_next(
        inject->config.inner_user, handle, out_message);
    if (status == NINLIL_BEARER_OK) {
        inject->recv_count += 1u;
        if (inject->config.mode == NINLIL_POSIX_LOOPBACK_INJECT_MODE_DROP_ACK
            && out_message->kind == NINLIL_BEARER_MESSAGE_RECEIPT
            && inject->drops_used < inject->config.drop_budget) {
            inject->drops_used += 1u;
            inject->drop_count += 1u;
            inject->config.inner_bearer->release_received(
                inject->config.inner_user, handle, out_message);
            return NINLIL_BEARER_EMPTY;
        }
    }
    return status;
}

static void inject_release(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    inject->config.inner_bearer->release_received(
        inject->config.inner_user, handle, message);
}

static ninlil_bearer_status_t inject_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    return inject->config.inner_bearer->state(
        inject->config.inner_user, handle, out_state);
}

static ninlil_tx_gate_status_t inject_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    return inject->config.inner_tx_gate->acquire(
        inject->config.inner_user, request, now, out_permit);
}

static void inject_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    ninlil_posix_loopback_bearer_inject_t *inject =
        (ninlil_posix_loopback_bearer_inject_t *)user;
    inject->config.inner_tx_gate->release_unused(inject->config.inner_user, permit);
}

ninlil_posix_loopback_bearer_inject_t *ninlil_posix_loopback_bearer_inject_create(
    const ninlil_posix_loopback_bearer_inject_config_t *config)
{
    ninlil_posix_loopback_bearer_inject_t *inject;

    if (config == NULL || config->inner_bearer == NULL
        || config->inner_tx_gate == NULL) {
        return NULL;
    }
    inject = (ninlil_posix_loopback_bearer_inject_t *)calloc(1u, sizeof(*inject));
    if (inject == NULL) {
        return NULL;
    }
    inject->config = *config;
    inject->bearer_ops.abi_version = NINLIL_ABI_VERSION;
    inject->bearer_ops.struct_size = (uint16_t)sizeof(inject->bearer_ops);
    inject->bearer_ops.user = inject;
    inject->bearer_ops.open = inject_open;
    inject->bearer_ops.close = inject_close;
    inject->bearer_ops.send = inject_send;
    inject->bearer_ops.receive_next = inject_receive;
    inject->bearer_ops.release_received = inject_release;
    inject->bearer_ops.state = inject_state;
    inject->tx_gate_ops.abi_version = NINLIL_ABI_VERSION;
    inject->tx_gate_ops.struct_size = (uint16_t)sizeof(inject->tx_gate_ops);
    inject->tx_gate_ops.user = inject;
    inject->tx_gate_ops.acquire = inject_tx_acquire;
    inject->tx_gate_ops.release_unused = inject_tx_release;
    return inject;
}

void ninlil_posix_loopback_bearer_inject_destroy(
    ninlil_posix_loopback_bearer_inject_t *inject)
{
    delayed_frame_t *frame;

    if (inject == NULL) {
        return;
    }
    while (inject->delayed != NULL) {
        frame = inject->delayed;
        inject->delayed = frame->next;
        free_delayed(frame);
    }
    free(inject);
}

const ninlil_bearer_ops_t *ninlil_posix_loopback_bearer_inject_bearer_ops(
    ninlil_posix_loopback_bearer_inject_t *inject)
{
    return inject == NULL ? NULL : &inject->bearer_ops;
}

const ninlil_tx_gate_ops_t *ninlil_posix_loopback_bearer_inject_tx_gate_ops(
    ninlil_posix_loopback_bearer_inject_t *inject)
{
    return inject == NULL ? NULL : &inject->tx_gate_ops;
}

uint64_t ninlil_posix_loopback_bearer_inject_send_count(
    const ninlil_posix_loopback_bearer_inject_t *inject)
{
    return inject == NULL ? 0u : inject->send_count;
}

uint64_t ninlil_posix_loopback_bearer_inject_recv_count(
    const ninlil_posix_loopback_bearer_inject_t *inject)
{
    return inject == NULL ? 0u : inject->recv_count;
}

uint64_t ninlil_posix_loopback_bearer_inject_drop_count(
    const ninlil_posix_loopback_bearer_inject_t *inject)
{
    return inject == NULL ? 0u : inject->drop_count;
}
