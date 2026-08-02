#include "composition_v1_test_fixture.h"
#include "runtime_internal.h"

#include <stdio.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct composition_test_link {
    ninlil_composition_v1_t *composition;
    ninlil_id128_t clock_epoch_id;
    ninlil_status_t reentry_status;
    uint32_t close_calls;
} composition_test_link_t;

static ninlil_fabric_link_status_t test_link_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    if (user == NULL || out_handle == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    *out_handle = user;
    return NINLIL_FABRIC_LINK_OK;
}

static void test_link_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    composition_test_link_t *link = (composition_test_link_t *)user;
    if (link != NULL && handle == user) {
        link->close_calls++;
    }
}

static ninlil_fabric_link_status_t test_link_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    (void)user;
    (void)handle;
    (void)packet;
    if (out_token != NULL) {
        *out_token = NULL;
    }
    return NINLIL_FABRIC_LINK_WOULD_BLOCK;
}

static ninlil_fabric_link_status_t test_link_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    (void)user;
    (void)handle;
    (void)token;
    if (out_completion != NULL) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    }
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t test_link_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    (void)user;
    (void)handle;
    (void)token;
    return NINLIL_FABRIC_LINK_OK;
}

static void test_link_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    (void)user;
    (void)handle;
    (void)token;
}

static ninlil_fabric_link_status_t test_link_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    composition_test_link_t *link = (composition_test_link_t *)user;
    ninlil_runtime_t *runtime = NULL;

    (void)handle;
    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    link->reentry_status = ninlil_composition_v1_runtime(
        link->composition, &runtime);
    return NINLIL_FABRIC_LINK_EMPTY;
}

static void test_link_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    (void)user;
    (void)handle;
    (void)receive_token;
}

static ninlil_fabric_link_status_t test_link_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    composition_test_link_t *link = (composition_test_link_t *)user;

    if (handle != user || out_state == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    out_state->availability_epoch = 1u;
    out_state->availability_clock_epoch_id = link->clock_epoch_id;
    out_state->available_until_ms = UINT64_C(1000000);
    out_state->available = 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static void fill_link(
    const ninlil_time_sample_t *now,
    composition_test_link_t *link,
    ninlil_fabric_link_descriptor_v1_t *descriptor,
    ninlil_fabric_packet_link_ops_v1_t *ops)
{
    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    composition_test_set_id(&descriptor->instance_id, 0x70u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    descriptor->descriptor_revision = 1u;
    (void)memset(descriptor->descriptor_digest, 0x11, 32u);
    composition_test_set_id(&descriptor->security_profile_id, 0x80u);
    descriptor->security_capability_flags = NINLIL_FABRIC_SECURITY_INTEGRITY;
    (void)memset(descriptor->security_binding_digest, 0x22, 32u);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id = now->clock_epoch_id;
    descriptor->attestation_expires_at_ms = UINT64_C(1000000);
    (void)memset(descriptor->attestation_digest, 0x33, 32u);
    composition_test_set_id(
        &descriptor->authenticated_peer_runtime_id, 0x90u);
    composition_test_set_id(&descriptor->attachment_authority_id, 0xa0u);
    (void)memset(descriptor->attachment_binding_digest, 0x44, 32u);
    descriptor->maximum_packet_bytes = 1925u;
    descriptor->maximum_transfer_bytes = 1925u;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    (void)memset(descriptor->configuration_digest, 0x55, 32u);

    (void)memset(ops, 0, sizeof(*ops));
    ops->api_version = NINLIL_FABRIC_API_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = link;
    ops->open = test_link_open;
    ops->close = test_link_close;
    ops->start_send = test_link_start_send;
    ops->poll_send = test_link_poll_send;
    ops->cancel_send = test_link_cancel_send;
    ops->release_send = test_link_release_send;
    ops->receive_next = test_link_receive_next;
    ops->release_received = test_link_release_received;
    ops->state = test_link_state;
    link->clock_epoch_id = now->clock_epoch_id;
}

static void init_budget(
    ninlil_composition_step_budget_v1_t *budget,
    uint32_t fabric_work,
    uint32_t reliability_work)
{
    (void)memset(budget, 0, sizeof(*budget));
    budget->api_version = NINLIL_COMPOSITION_API_VERSION;
    budget->struct_size = (uint16_t)sizeof(*budget);
    budget->runtime.abi_version = NINLIL_ABI_VERSION;
    budget->runtime.struct_size = (uint16_t)sizeof(budget->runtime);
    budget->fabric_work = fabric_work;
    budget->reliability_work = reliability_work;
}

static void init_result(ninlil_composition_step_result_v1_t *result)
{
    (void)memset(result, 0xa5, sizeof(*result));
    result->api_version = NINLIL_COMPOSITION_API_VERSION;
    result->struct_size = (uint16_t)sizeof(*result);
}

static int workspace_is_zero(const void *workspace, uint32_t bytes)
{
    const uint8_t *value = (const uint8_t *)workspace;
    uint32_t i;

    for (i = 0u; i < bytes; ++i) {
        if (value[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    static const uint8_t storage_namespace[] = "composition-lifecycle";
    composition_test_fixture_t fixture;
    ninlil_composition_v1_t *composition = NULL;
    ninlil_runtime_t *runtime = NULL;
    ninlil_fabric_v1_t *fabric = NULL;
    ninlil_composition_step_budget_v1_t budget;
    ninlil_composition_step_result_v1_t result;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_link_registration_v1_t *registration = NULL;
    composition_test_link_t link;
    ninlil_time_sample_t now;
    uint64_t clock_calls;
    uint32_t done = 0u;

    REQUIRE(composition_test_fixture_init(
        &fixture,
        NULL,
        0x60u,
        storage_namespace,
        (uint32_t)sizeof(storage_namespace) - 1u));
    REQUIRE(ninlil_composition_v1_create(
                NINLIL_COMPOSITION_PROFILE_1,
                &fixture.config,
                &fixture.platform,
                fixture.workspace,
                fixture.workspace_bytes,
                &composition)
        == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_runtime(composition, &runtime) == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_fabric(composition, &fabric) == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_destroy(composition) == NINLIL_E_WOULD_BLOCK);

    init_budget(&budget, 0u, 1u);
    init_result(&result);
    clock_calls = ninlil_test_clock_call_count(fixture.clock);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(ninlil_test_clock_call_count(fixture.clock) == clock_calls);
    REQUIRE(result.runtime.health == NINLIL_HEALTH_OK);
    REQUIRE(result.fabric_work_done == 0u);
    REQUIRE(result.reliability_work_done == 0u);
    REQUIRE(result.more_work == 0u && result.reserved_zero == 0u);

    runtime->pending_work = 1u;
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(result.more_work == 1u);
    runtime->pending_work = 0u;

    init_budget(&budget, 0u, 0u);
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(result.fabric_work_done == 0u);
    REQUIRE(result.reliability_work_done == 0u);

    init_budget(&budget, 0u, 1u);
    init_result(&result);
    ninlil_test_execution_set_context_id(fixture.execution, 2u);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_E_WRONG_THREAD);
    REQUIRE(result.fabric_work_done == 0u && result.more_work == 0u);
    ninlil_test_execution_set_context_id(fixture.execution, 1u);

    /* RAM-only projection must report a terminal release even at budget 0. */
    runtime->transactions[0].in_use = 1u;
    runtime->transactions[0].terminal = 1u;
    runtime->transactions[0].record_revision = 1u;
    composition_test_set_id(&runtime->transactions[0].transaction_id, 0xb0u);
    init_budget(&budget, 0u, 1u);
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(result.fabric_work_done == 0u && result.more_work == 1u);
    init_budget(&budget, 1u, 0u);
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(result.fabric_work_done == 0u && result.more_work == 1u);
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(result.fabric_work_done == 0u && result.more_work == 0u);
    (void)memset(&runtime->transactions[0], 0, sizeof(runtime->transactions[0]));

    (void)memset(&now, 0, sizeof(now));
    REQUIRE(fixture.platform.clock->now(fixture.platform.clock->user, &now)
        == NINLIL_PORT_OK);
    (void)memset(&link, 0, sizeof(link));
    link.composition = composition;
    fill_link(&now, &link, &descriptor, &ops);
    REQUIRE(ninlil_fabric_v1_register_link(
                fabric, &descriptor, &ops, &registration)
        == NINLIL_FABRIC_OK);
    REQUIRE(registration != NULL);

    init_budget(&budget, 1u, 0u);
    init_result(&result);
    REQUIRE(ninlil_composition_v1_step(composition, &budget, &result)
        == NINLIL_OK);
    REQUIRE(result.fabric_work_done == 1u);
    REQUIRE(result.more_work == 0u);
    REQUIRE(link.reentry_status == NINLIL_E_REENTRANT);

    REQUIRE(ninlil_composition_v1_close_begin(composition)
        == NINLIL_E_CONFLICT);
    REQUIRE(link.close_calls == 0u);
    runtime = NULL;
    REQUIRE(ninlil_composition_v1_runtime(composition, &runtime) == NINLIL_OK);
    REQUIRE(runtime != NULL);
    REQUIRE(ninlil_fabric_v1_unregister_begin(fabric, registration)
        == NINLIL_FABRIC_OK);
    REQUIRE(ninlil_fabric_v1_unregister_poll(fabric, registration, &done)
        == NINLIL_FABRIC_OK);
    REQUIRE(done == 1u && link.close_calls == 1u);

    /* A consumed Runtime COMMIT_UNKNOWN is reported only when drain finishes. */
    runtime->commit_unknown_fence = 1u;
    REQUIRE(ninlil_composition_v1_close_begin(composition) == NINLIL_OK);
    REQUIRE(ninlil_composition_v1_runtime(composition, &runtime)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_composition_v1_destroy(composition) == NINLIL_E_WOULD_BLOCK);
    done = 0u;
    REQUIRE(ninlil_composition_v1_close_poll(composition, 64u, &done)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(done == 1u);
    REQUIRE(ninlil_composition_v1_destroy(composition) == NINLIL_OK);
    REQUIRE(workspace_is_zero(fixture.workspace, fixture.workspace_bytes));

    composition_test_fixture_destroy(&fixture);
    (void)printf("composition_v1_lifecycle_test: PASS\n");
    return 0;
}
