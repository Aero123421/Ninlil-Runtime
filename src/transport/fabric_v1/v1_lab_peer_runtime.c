#include "v1_lab_peer_runtime.h"

#include "v1_lab_fabric.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PEER_RUNTIME_MAGIC UINT32_C(0x4e505231)
#define PEER_RUNTIME_STATE_PREPARED ((uint8_t)1u)
#define PEER_RUNTIME_STATE_BOUND ((uint8_t)2u)
#define PEER_RUNTIME_STATE_ACTIVE ((uint8_t)3u)
#define PEER_RUNTIME_STATE_FENCED ((uint8_t)4u)
#define PEER_RUNTIME_STATE_CLOSING ((uint8_t)5u)
#define PEER_RUNTIME_STATE_CLOSED ((uint8_t)6u)

#define PEER_RUNTIME_PATH_MAX ((uint8_t)2u)
#define PEER_RUNTIME_PERMIT_LIFETIME_MS UINT64_C(5000)
#define PEER_RUNTIME_GRANT_LIFETIME_MS UINT64_C(60000)
#define PEER_RUNTIME_EVENT_SPOOL_COUNT ((uint32_t)8u)
#define PEER_RUNTIME_EVENT_SPOOL_BYTES ((uint64_t)4096u)

typedef struct ninlil_v1_lab_peer_runtime_impl {
    uint32_t magic;
    uint8_t state;
    uint8_t pair_slot;
    uint8_t service_count;
    uint8_t registration_count;
    uint8_t unregister_started[PEER_RUNTIME_PATH_MAX];
    uint8_t composition_close_started;
    uint8_t reserved_state;
    ninlil_r7_crypto_provider crypto;
    ninlil_platform_ops_t platform;
    ninlil_tx_gate_ops_t tx_gate;
    ninlil_origin_authorization_ops_t origin;
    ninlil_service_callbacks_t desired_callbacks;
    void *composition_workspace;
    uint32_t composition_workspace_bytes;
    uint8_t storage_namespace[20];
    ninlil_v1_lab_binding_t binding;
    const ninlil_v1_lab_endpoint_t *local_endpoint;
    const ninlil_v1_lab_endpoint_t *controller_endpoint;
    ninlil_v1_lab_radio_packet_link_t *radio;
    ninlil_composition_v1_t *composition;
    ninlil_runtime_t *runtime;
    ninlil_fabric_v1_t *fabric;
    ninlil_service_t *services[NINLIL_V1_LAB_SERVICE_MAX];
    uint8_t service_slots[NINLIL_V1_LAB_SERVICE_MAX];
    ninlil_fabric_link_registration_v1_t
        *registrations[PEER_RUNTIME_PATH_MAX];
} ninlil_v1_lab_peer_runtime_impl_t;

_Static_assert(
    sizeof(ninlil_v1_lab_peer_runtime_impl_t)
        <= NINLIL_V1_LAB_PEER_RUNTIME_OBJECT_BYTES,
    "V1 peer runtime object ceiling");
_Static_assert(
    _Alignof(ninlil_v1_lab_peer_runtime_impl_t)
        <= _Alignof(ninlil_v1_lab_peer_runtime_t),
    "V1 peer runtime object alignment");

static ninlil_v1_lab_peer_runtime_impl_t *peer_impl(
    ninlil_v1_lab_peer_runtime_t *runtime)
{
    return runtime == NULL
        ? NULL
        : (ninlil_v1_lab_peer_runtime_impl_t *)(void *)runtime->opaque;
}

static void secure_clear(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;

    if (pointer == NULL) {
        return;
    }
    while (length > 0u) {
        *bytes = 0u;
        ++bytes;
        --length;
    }
}

static int bytes_are_zero(const void *pointer, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)pointer;
    uint8_t aggregate = 0u;
    size_t index;

    if (pointer == NULL) {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        aggregate = (uint8_t)(aggregate | bytes[index]);
    }
    return aggregate == 0u;
}

static int id_nonzero(const uint8_t id[16])
{
    return id != NULL && !bytes_are_zero(id, 16u);
}

static int platform_shape_valid(const ninlil_platform_ops_t *platform)
{
    return platform != NULL
        && platform->abi_version == NINLIL_ABI_VERSION
        && platform->struct_size == (uint16_t)sizeof(*platform)
        && platform->allocator != NULL && platform->execution != NULL
        && platform->clock != NULL && platform->entropy != NULL
        && platform->storage != NULL && platform->bearer == NULL
        && platform->tx_gate == NULL
        && platform->origin_authorization == NULL
        && platform->allocator->allocate != NULL
        && platform->allocator->deallocate != NULL
        && platform->execution->current_context_id != NULL
        && platform->clock->now != NULL && platform->entropy->fill != NULL;
}

static int callbacks_shape_valid(
    const ninlil_service_callbacks_t *callbacks)
{
    return callbacks != NULL
        && callbacks->abi_version == NINLIL_ABI_VERSION
        && callbacks->struct_size == (uint16_t)sizeof(*callbacks)
        && callbacks->on_delivery != NULL
        && callbacks->on_reconcile != NULL;
}

static const ninlil_v1_lab_endpoint_t *endpoint_for_side(
    const ninlil_v1_lab_binding_t *binding, uint8_t side)
{
    if (binding == NULL) {
        return NULL;
    }
    if (side == NINLIL_V1_LAB_SIDE_A) {
        return &binding->endpoint_a;
    }
    if (side == NINLIL_V1_LAB_SIDE_B) {
        return &binding->endpoint_b;
    }
    return NULL;
}

static uint8_t opposite_side(uint8_t side)
{
    if (side == NINLIL_V1_LAB_SIDE_A) {
        return NINLIL_V1_LAB_SIDE_B;
    }
    if (side == NINLIL_V1_LAB_SIDE_B) {
        return NINLIL_V1_LAB_SIDE_A;
    }
    return 0u;
}

static int flow_matches_profile(
    const ninlil_v1_lab_peer_runtime_impl_t *runtime,
    const ninlil_v1_lab_service_row_t *row)
{
    const ninlil_v1_lab_endpoint_t *source;
    const ninlil_v1_lab_endpoint_t *target;

    if (runtime == NULL || row == NULL || runtime->local_endpoint == NULL
        || runtime->controller_endpoint == NULL) {
        return 0;
    }
    if (row->flow == NINLIL_V1_LAB_FLOW_A_TO_B) {
        source = &runtime->binding.endpoint_a;
        target = &runtime->binding.endpoint_b;
    } else if (row->flow == NINLIL_V1_LAB_FLOW_B_TO_A) {
        source = &runtime->binding.endpoint_b;
        target = &runtime->binding.endpoint_a;
    } else {
        return 0;
    }
    if (row->family == NINLIL_FAMILY_DESIRED_STATE) {
        return row->direction == NINLIL_DIRECTION_DOWNLINK
            && memcmp(source->runtime_id,
                   runtime->controller_endpoint->runtime_id, 16u)
                == 0
            && memcmp(target->runtime_id,
                   runtime->local_endpoint->runtime_id, 16u)
                == 0;
    }
    if (row->family == NINLIL_FAMILY_EVENT_FACT) {
        return row->direction == NINLIL_DIRECTION_UPLINK
            && memcmp(source->runtime_id,
                   runtime->local_endpoint->runtime_id, 16u)
                == 0
            && memcmp(target->runtime_id,
                   runtime->controller_endpoint->runtime_id, 16u)
                == 0;
    }
    return 0;
}

static int identity_equal(
    const ninlil_local_identity_t *identity,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    return identity != NULL && endpoint != NULL
        && identity->abi_version == NINLIL_ABI_VERSION
        && identity->struct_size == (uint16_t)sizeof(*identity)
        && identity->reserved_zero == 0u
        && identity->flags == endpoint->identity_flags
        && identity->binding_epoch == endpoint->binding_epoch
        && identity->membership_epoch == endpoint->membership_epoch
        && memcmp(identity->device_id.bytes, endpoint->device_id, 16u) == 0
        && memcmp(identity->installation_id.bytes,
               endpoint->installation_id, 16u)
            == 0
        && memcmp(identity->site_domain_id.bytes, endpoint->site_id, 16u)
            == 0;
}

static int target_equal(
    const ninlil_concrete_target_t *target,
    const ninlil_v1_lab_endpoint_t *endpoint)
{
    return target != NULL && endpoint != NULL
        && target->abi_version == NINLIL_ABI_VERSION
        && target->struct_size == (uint16_t)sizeof(*target)
        && target->reserved_zero == 0u
        && target->flags == endpoint->identity_flags
        && target->binding_epoch == endpoint->binding_epoch
        && target->membership_epoch == endpoint->membership_epoch
        && memcmp(target->target_runtime_id.bytes,
               endpoint->runtime_id, 16u)
            == 0
        && memcmp(target->target_application_instance_id.bytes,
               endpoint->application_id, 16u)
            == 0
        && memcmp(target->device_id.bytes, endpoint->device_id, 16u) == 0
        && memcmp(target->installation_id.bytes,
               endpoint->installation_id, 16u)
            == 0
        && memcmp(target->site_domain_id.bytes, endpoint->site_id, 16u)
            == 0;
}

static int text_id_equal(
    const ninlil_text_id_t *identity,
    const uint8_t *expected,
    uint8_t expected_length)
{
    return identity != NULL && expected != NULL
        && identity->length == expected_length
        && memcmp(identity->bytes, expected, expected_length) == 0;
}

static const ninlil_v1_lab_service_row_t *find_event_row(
    const ninlil_v1_lab_peer_runtime_impl_t *runtime,
    const ninlil_service_identity_t *identity)
{
    uint8_t index;

    if (runtime == NULL || identity == NULL
        || identity->abi_version != NINLIL_ABI_VERSION
        || identity->struct_size != (uint16_t)sizeof(*identity)
        || identity->family != NINLIL_FAMILY_EVENT_FACT
        || identity->descriptor_digest.algorithm != NINLIL_DIGEST_SHA256
        || identity->descriptor_digest.reserved_zero != 0u) {
        return NULL;
    }
    for (index = 0u; index < runtime->binding.service_count; ++index) {
        const ninlil_v1_lab_service_row_t *row =
            &runtime->binding.services[index];

        if (row->family == NINLIL_FAMILY_EVENT_FACT
            && row->descriptor_revision == identity->descriptor_revision
            && row->schema_major == identity->schema_major
            && row->schema_minor == identity->schema_minor
            && text_id_equal(&identity->namespace_id,
                   row->namespace_id, row->namespace_length)
            && text_id_equal(&identity->service_id,
                   row->service_id, row->service_length)
            && text_id_equal(&identity->schema_id,
                   row->schema_id, row->schema_length)
            && memcmp(identity->descriptor_digest.bytes,
                   row->descriptor_digest, 32u)
                == 0) {
            return row;
        }
    }
    return NULL;
}

static int tx_request_valid(
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now)
{
    uint32_t maximum;

    if (request == NULL || now == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || now->reserved_zero != 0u
        || !id_nonzero(request->transaction_id.bytes)
        || !id_nonzero(request->attempt_id.bytes)
        || !id_nonzero(now->clock_epoch_id.bytes)) {
        return 0;
    }
    if (request->message_kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        maximum = NINLIL_V1_LAB_APPLICATION_MAX;
    } else if (request->message_kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
        maximum = NINLIL_V1_LAB_FABRIC_PACKET_MAX;
    } else {
        return 0;
    }
    return request->logical_bytes > 0u && request->logical_bytes <= maximum;
}

static ninlil_tx_gate_status_t peer_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_v1_lab_peer_runtime_impl_t *runtime =
        (ninlil_v1_lab_peer_runtime_impl_t *)user;
    ninlil_port_status_t entropy_status;

    if (out_permit != NULL) {
        (void)memset(out_permit, 0, sizeof(*out_permit));
    }
    if (runtime == NULL || runtime->magic != PEER_RUNTIME_MAGIC
        || runtime->state != PEER_RUNTIME_STATE_ACTIVE
        || out_permit == NULL || !tx_request_valid(request, now)
        || runtime->local_endpoint == NULL
        || memcmp(now->clock_epoch_id.bytes,
               runtime->local_endpoint->clock_epoch_id, 16u)
            != 0
        || now->now_ms > UINT64_MAX - PEER_RUNTIME_PERMIT_LIFETIME_MS) {
        return NINLIL_TX_GATE_DENIED;
    }
    out_permit->abi_version = NINLIL_ABI_VERSION;
    out_permit->struct_size = (uint16_t)sizeof(*out_permit);
    entropy_status = runtime->platform.entropy->fill(
        runtime->platform.entropy->user, out_permit->permit_id.bytes, 16u);
    if (entropy_status != NINLIL_PORT_OK
        || !id_nonzero(out_permit->permit_id.bytes)) {
        secure_clear(out_permit, sizeof(*out_permit));
        return entropy_status == NINLIL_PORT_TEMPORARY_FAILURE
            ? NINLIL_TX_GATE_TEMPORARY
            : NINLIL_TX_GATE_DENIED;
    }
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms =
        now->now_ms + PEER_RUNTIME_PERMIT_LIFETIME_MS;
    return NINLIL_TX_GATE_OK;
}

static void peer_tx_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    (void)user;
    (void)permit;
}

static ninlil_origin_auth_status_t peer_origin_evaluate(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    ninlil_v1_lab_peer_runtime_impl_t *runtime =
        (ninlil_v1_lab_peer_runtime_impl_t *)user;
    const ninlil_v1_lab_service_row_t *row;

    if (out_decision != NULL) {
        (void)memset(out_decision, 0, sizeof(*out_decision));
    }
    if (runtime == NULL || runtime->magic != PEER_RUNTIME_MAGIC
        || runtime->state != PEER_RUNTIME_STATE_ACTIVE
        || request == NULL || out_decision == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || request->environment != NINLIL_ENV_LAB
        || request->reserved_zero != 0u
        || request->now.abi_version != NINLIL_ABI_VERSION
        || request->now.struct_size != (uint16_t)sizeof(request->now)
        || request->now.trust != NINLIL_CLOCK_TRUSTED
        || request->now.reserved_zero != 0u
        || runtime->local_endpoint == NULL
        || runtime->controller_endpoint == NULL
        || memcmp(request->source.runtime_id.bytes,
               runtime->local_endpoint->runtime_id, 16u)
            != 0
        || memcmp(request->source.application_instance_id.bytes,
               runtime->local_endpoint->application_id, 16u)
            != 0
        || !identity_equal(&request->source.local_identity,
               runtime->local_endpoint)
        || !target_equal(&request->target, runtime->controller_endpoint)
        || request->payload_length == 0u
        || request->payload_length > NINLIL_V1_LAB_APPLICATION_MAX
        || request->required_evidence < NINLIL_EVIDENCE_RECEIVED
        || request->required_evidence > NINLIL_EVIDENCE_VERIFIED
        || memcmp(request->now.clock_epoch_id.bytes,
               runtime->local_endpoint->clock_epoch_id, 16u)
            != 0) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    row = find_event_row(runtime, &request->service);
    if (row == NULL || !flow_matches_profile(runtime, row)) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    if (request->now.now_ms > UINT64_MAX - PEER_RUNTIME_GRANT_LIFETIME_MS) {
        return NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE;
    }

    out_decision->abi_version = NINLIL_ABI_VERSION;
    out_decision->struct_size = (uint16_t)sizeof(*out_decision);
    out_decision->allowed = 1u;
    out_decision->reason = NINLIL_REASON_NONE;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    (void)memcpy(out_decision->provider_id.bytes,
        runtime->binding.pair_id, 16u);
    out_decision->provider_revision = runtime->binding.pair_generation;
    out_decision->decision_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(out_decision->decision_digest.bytes,
        runtime->binding.pair_binding_digest, 32u);
    (void)memcpy(out_decision->grant_id.bytes,
        runtime->binding.e2e_security_id, 16u);
    out_decision->grant_id.bytes[15] ^= row->slot;
    if (!id_nonzero(out_decision->provider_id.bytes)
        || !id_nonzero(out_decision->grant_id.bytes)
        || bytes_are_zero(out_decision->decision_digest.bytes, 32u)) {
        secure_clear(out_decision, sizeof(*out_decision));
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    out_decision->grant_revision = runtime->binding.pair_generation;
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    out_decision->valid_from_ms = request->now.now_ms;
    out_decision->expires_at_ms =
        request->now.now_ms + PEER_RUNTIME_GRANT_LIFETIME_MS;
    out_decision->max_payload_bytes = NINLIL_V1_LAB_APPLICATION_MAX;
    out_decision->max_active_spool_count = PEER_RUNTIME_EVENT_SPOOL_COUNT;
    out_decision->max_active_spool_bytes = PEER_RUNTIME_EVENT_SPOOL_BYTES;
    out_decision->rate_window_ms = NINLIL_V1_LAB_ADMISSION_WINDOW_MS;
    out_decision->max_admissions_per_window =
        NINLIL_V1_LAB_ADMISSIONS_PER_WINDOW;
    out_decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static ninlil_runtime_config_t build_runtime_config(
    ninlil_v1_lab_peer_runtime_impl_t *runtime)
{
    ninlil_runtime_config_t config;
    const ninlil_v1_lab_endpoint_t *endpoint = runtime->local_endpoint;

    (void)memset(&config, 0, sizeof(config));
    config.abi_version = NINLIL_ABI_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.role = NINLIL_ROLE_ENDPOINT;
    config.environment = NINLIL_ENV_LAB;
    (void)memcpy(config.runtime_id.bytes, endpoint->runtime_id, 16u);
    config.local_identity.abi_version = NINLIL_ABI_VERSION;
    config.local_identity.struct_size =
        (uint16_t)sizeof(config.local_identity);
    config.local_identity.flags = endpoint->identity_flags;
    (void)memcpy(config.local_identity.device_id.bytes,
        endpoint->device_id, 16u);
    (void)memcpy(config.local_identity.installation_id.bytes,
        endpoint->installation_id, 16u);
    (void)memcpy(config.local_identity.site_domain_id.bytes,
        endpoint->site_id, 16u);
    config.local_identity.binding_epoch = endpoint->binding_epoch;
    config.local_identity.membership_epoch = endpoint->membership_epoch;
    config.storage_namespace.data = runtime->storage_namespace;
    config.storage_namespace.length = sizeof(runtime->storage_namespace);
    config.limits.abi_version = NINLIL_ABI_VERSION;
    config.limits.struct_size = (uint16_t)sizeof(config.limits);
    config.limits.max_services = runtime->binding.service_count;
    config.limits.max_nonterminal_transactions = 8u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes =
        NINLIL_V1_LAB_APPLICATION_MAX;
    config.limits.max_durable_outbox_payload_bytes = 0u;
    config.limits.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 8u;
    config.limits.max_nonterminal_deliveries = 8u;
    config.limits.max_event_spool_count = PEER_RUNTIME_EVENT_SPOOL_COUNT;
    config.limits.max_event_spool_bytes = PEER_RUNTIME_EVENT_SPOOL_BYTES;
    config.limits.max_result_cache_entries = 8u;
    config.limits.max_retained_dispositions = 8u;
    config.limits.max_ingress_per_step = 4u;
    config.limits.max_callbacks_per_step = 4u;
    config.limits.max_state_transitions_per_step = 8u;
    config.limits.max_bearer_sends_per_step = 4u;
    config.limits.max_deferred_tokens = 4u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static int composition_step_once(
    ninlil_v1_lab_peer_runtime_impl_t *runtime,
    uint32_t runtime_work)
{
    ninlil_composition_step_budget_v1_t budget;
    ninlil_composition_step_result_v1_t result;

    if (runtime == NULL || runtime->composition == NULL) {
        return 0;
    }
    (void)memset(&budget, 0, sizeof(budget));
    budget.api_version = NINLIL_COMPOSITION_API_VERSION;
    budget.struct_size = (uint16_t)sizeof(budget);
    budget.runtime.abi_version = NINLIL_ABI_VERSION;
    budget.runtime.struct_size = (uint16_t)sizeof(budget.runtime);
    if (runtime_work != 0u) {
        budget.runtime.max_ingress_messages = 4u;
        budget.runtime.max_callbacks = 4u;
        budget.runtime.max_state_transitions = 8u;
        budget.runtime.max_bearer_sends = 4u;
    }
    budget.fabric_work = 64u;
    budget.reliability_work = 64u;
    (void)memset(&result, 0, sizeof(result));
    result.api_version = NINLIL_COMPOSITION_API_VERSION;
    result.struct_size = (uint16_t)sizeof(result);
    return ninlil_composition_v1_step(
               runtime->composition, &budget, &result)
        == NINLIL_OK;
}

static int flow_already_registered(
    const uint8_t flows[PEER_RUNTIME_PATH_MAX],
    uint8_t count,
    uint8_t flow)
{
    uint8_t index;

    for (index = 0u; index < count; ++index) {
        if (flows[index] == flow) {
            return 1;
        }
    }
    return 0;
}

static ninlil_v1_lab_peer_runtime_status_t activate_runtime(
    ninlil_v1_lab_peer_runtime_impl_t *runtime)
{
    ninlil_runtime_config_t config;
    ninlil_service_callbacks_t event_callbacks;
    ninlil_time_sample_t sample;
    uint8_t flows[PEER_RUNTIME_PATH_MAX];
    uint8_t flow_count = 0u;
    uint8_t index;

    (void)memset(flows, 0, sizeof(flows));
    (void)memset(&sample, 0, sizeof(sample));
    if (runtime == NULL || runtime->state != PEER_RUNTIME_STATE_BOUND
        || runtime->local_endpoint == NULL
        || runtime->controller_endpoint == NULL || runtime->radio == NULL
        || runtime->platform.clock->now(runtime->platform.clock->user,
               &sample)
            != NINLIL_PORT_OK
        || sample.trust != NINLIL_CLOCK_TRUSTED
        || memcmp(sample.clock_epoch_id.bytes,
               runtime->local_endpoint->clock_epoch_id, 16u)
            != 0) {
        return NINLIL_V1_LAB_PEER_RUNTIME_PLATFORM;
    }
    for (index = 0u; index < runtime->binding.service_count; ++index) {
        if (!flow_matches_profile(runtime, &runtime->binding.services[index])) {
            return NINLIL_V1_LAB_PEER_RUNTIME_BINDING;
        }
    }

    runtime->tx_gate.abi_version = NINLIL_ABI_VERSION;
    runtime->tx_gate.struct_size = (uint16_t)sizeof(runtime->tx_gate);
    runtime->tx_gate.user = runtime;
    runtime->tx_gate.acquire = peer_tx_acquire;
    runtime->tx_gate.release_unused = peer_tx_release_unused;
    runtime->origin.abi_version = NINLIL_ABI_VERSION;
    runtime->origin.struct_size = (uint16_t)sizeof(runtime->origin);
    runtime->origin.user = runtime;
    runtime->origin.evaluate = peer_origin_evaluate;
    runtime->platform.tx_gate = &runtime->tx_gate;
    runtime->platform.origin_authorization = &runtime->origin;

    config = build_runtime_config(runtime);
    if (ninlil_composition_v1_create(NINLIL_COMPOSITION_PROFILE_1,
            &config, &runtime->platform, runtime->composition_workspace,
            runtime->composition_workspace_bytes, &runtime->composition)
            != NINLIL_OK
        || ninlil_composition_v1_runtime(
               runtime->composition, &runtime->runtime)
            != NINLIL_OK
        || ninlil_composition_v1_fabric(
               runtime->composition, &runtime->fabric)
            != NINLIL_OK) {
        return NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
    }

    (void)memset(&event_callbacks, 0, sizeof(event_callbacks));
    event_callbacks.abi_version = NINLIL_ABI_VERSION;
    event_callbacks.struct_size = (uint16_t)sizeof(event_callbacks);
    for (index = 0u; index < runtime->binding.service_count; ++index) {
        ninlil_service_descriptor_t descriptor;
        const ninlil_service_callbacks_t *callbacks;

        (void)memset(&descriptor, 0, sizeof(descriptor));
        if (ninlil_v1_lab_fabric_build_descriptor(&runtime->binding,
                runtime->local_endpoint->runtime_id, index, &descriptor)
                != NINLIL_V1_LAB_FABRIC_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_SERVICE;
        }
        callbacks = descriptor.family == NINLIL_FAMILY_DESIRED_STATE
            ? &runtime->desired_callbacks
            : &event_callbacks;
        if (ninlil_service_register(runtime->runtime, &descriptor,
                callbacks, &runtime->services[index])
            != NINLIL_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_SERVICE;
        }
        runtime->service_slots[index] = runtime->binding.services[index].slot;
        runtime->service_count += 1u;
    }

    for (index = 0u; index < runtime->binding.service_count; ++index) {
        const ninlil_v1_lab_service_row_t *row =
            &runtime->binding.services[index];

        if (!flow_already_registered(flows, flow_count, row->flow)) {
            ninlil_fabric_link_descriptor_v1_t descriptor;
            ninlil_fabric_link_state_v1_t state;
            const ninlil_fabric_packet_link_ops_v1_t *ops = NULL;
            const uint8_t *path_id = NULL;

            if (flow_count >= PEER_RUNTIME_PATH_MAX) {
                return NINLIL_V1_LAB_PEER_RUNTIME_FABRIC;
            }
            (void)memset(&descriptor, 0, sizeof(descriptor));
            (void)memset(&state, 0, sizeof(state));
            if (ninlil_v1_lab_fabric_build_path(&runtime->crypto,
                    &runtime->binding, runtime->local_endpoint->runtime_id,
                    row->flow, &descriptor, &state)
                    != NINLIL_V1_LAB_FABRIC_OK
                || ninlil_v1_lab_radio_packet_link_path(runtime->radio,
                       runtime->pair_slot, row->flow, &path_id, &ops)
                    != NINLIL_V1_LAB_RADIO_LINK_OK
                || path_id == NULL || ops == NULL
                || memcmp(path_id, descriptor.instance_id.bytes, 16u) != 0
                || ninlil_fabric_v1_register_link(runtime->fabric,
                       &descriptor, ops,
                       &runtime->registrations[flow_count])
                    != NINLIL_FABRIC_OK) {
                return NINLIL_V1_LAB_PEER_RUNTIME_FABRIC;
            }
            flows[flow_count] = row->flow;
            flow_count += 1u;
            runtime->registration_count = flow_count;
        }
    }

    for (index = 0u; index < runtime->binding.service_count; ++index) {
        ninlil_fabric_path_policy_v1_t policy;
        ninlil_fabric_authority_binding_v1_t authority;

        (void)memset(&policy, 0, sizeof(policy));
        (void)memset(&authority, 0, sizeof(authority));
        if (ninlil_v1_lab_fabric_build_service(&runtime->crypto,
                &runtime->binding, runtime->local_endpoint->runtime_id,
                index, &policy, &authority)
                != NINLIL_V1_LAB_FABRIC_OK
            || ninlil_fabric_v1_policy_put(runtime->fabric, &policy)
                != NINLIL_FABRIC_OK
            || ninlil_fabric_v1_authority_put(runtime->fabric, &authority)
                != NINLIL_FABRIC_OK) {
            secure_clear(&policy, sizeof(policy));
            secure_clear(&authority, sizeof(authority));
            return NINLIL_V1_LAB_PEER_RUNTIME_FABRIC;
        }
        secure_clear(&policy, sizeof(policy));
        secure_clear(&authority, sizeof(authority));
    }
    runtime->state = PEER_RUNTIME_STATE_ACTIVE;
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_prepare(
    ninlil_v1_lab_peer_runtime_t *runtime,
    const ninlil_v1_lab_peer_runtime_config_t *config)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    uint32_t required_bytes = 0u;
    uint32_t required_alignment = 0u;

    if (impl == NULL || config == NULL || config->crypto == NULL
        || !bytes_are_zero(runtime, sizeof(*runtime))
        || ninlil_r7_crypto_provider_validate(config->crypto)
            != NINLIL_R7_CRYPTO_OK
        || !platform_shape_valid(config->platform_template)
        || !callbacks_shape_valid(config->desired_callbacks)
        || config->composition_workspace == NULL
        || ninlil_composition_v1_workspace_required(
               NINLIL_COMPOSITION_PROFILE_1,
               &required_bytes,
               &required_alignment)
            != NINLIL_OK
        || required_bytes == 0u || required_alignment == 0u
        || config->composition_workspace_bytes < required_bytes
        || ((uintptr_t)config->composition_workspace
                & (uintptr_t)(required_alignment - 1u))
            != 0u) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }

    impl->magic = PEER_RUNTIME_MAGIC;
    impl->state = PEER_RUNTIME_STATE_PREPARED;
    impl->crypto = *config->crypto;
    impl->platform = *config->platform_template;
    impl->desired_callbacks = *config->desired_callbacks;
    impl->composition_workspace = config->composition_workspace;
    impl->composition_workspace_bytes = required_bytes;
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}

int ninlil_v1_lab_peer_runtime_pair_ready(
    void *user,
    ninlil_v1_lab_radio_packet_link_t *radio,
    uint8_t pair_slot,
    const uint8_t *encoded_binding,
    size_t encoded_length)
{
    ninlil_v1_lab_peer_runtime_t *runtime =
        (ninlil_v1_lab_peer_runtime_t *)user;
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    ninlil_v1_lab_binding_t decoded;
    uint8_t local_side;

    (void)memset(&decoded, 0, sizeof(decoded));
    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC
        || impl->state != PEER_RUNTIME_STATE_PREPARED || radio == NULL
        || encoded_binding == NULL || pair_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX
        || ninlil_v1_lab_binding_decode(&impl->crypto, encoded_binding,
               encoded_length, &decoded)
            != NINLIL_V1_LAB_BINDING_OK) {
        ninlil_v1_lab_binding_clear(&decoded);
        return 1;
    }
    local_side = opposite_side(decoded.controller_side);
    if (local_side == 0u || decoded.service_count == 0u
        || decoded.service_count > NINLIL_V1_LAB_SERVICE_MAX) {
        ninlil_v1_lab_binding_clear(&decoded);
        return 1;
    }

    impl->binding = decoded;
    secure_clear(&decoded, sizeof(decoded));
    impl->local_endpoint = endpoint_for_side(&impl->binding, local_side);
    impl->controller_endpoint =
        endpoint_for_side(&impl->binding, impl->binding.controller_side);
    if (impl->local_endpoint == NULL || impl->controller_endpoint == NULL
        || !id_nonzero(impl->local_endpoint->runtime_id)
        || !id_nonzero(impl->controller_endpoint->runtime_id)) {
        ninlil_v1_lab_binding_clear(&impl->binding);
        impl->local_endpoint = NULL;
        impl->controller_endpoint = NULL;
        return 1;
    }
    (void)memcpy(impl->storage_namespace, "NLP1", 4u);
    (void)memcpy(impl->storage_namespace + 4u,
        impl->local_endpoint->runtime_id, 16u);
    impl->radio = radio;
    impl->pair_slot = pair_slot;
    impl->state = PEER_RUNTIME_STATE_BOUND;
    return 0;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_step(
    ninlil_v1_lab_peer_runtime_t *runtime)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    ninlil_v1_lab_peer_runtime_status_t status;

    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }
    if (impl->state == PEER_RUNTIME_STATE_PREPARED) {
        return NINLIL_V1_LAB_PEER_RUNTIME_WAITING;
    }
    if (impl->state == PEER_RUNTIME_STATE_BOUND) {
        status = activate_runtime(impl);
        if (status != NINLIL_V1_LAB_PEER_RUNTIME_OK) {
            impl->state = PEER_RUNTIME_STATE_FENCED;
            return status;
        }
    }
    if (impl->state == PEER_RUNTIME_STATE_FENCED) {
        return NINLIL_V1_LAB_PEER_RUNTIME_FENCED;
    }
    if (impl->state == PEER_RUNTIME_STATE_CLOSING) {
        return NINLIL_V1_LAB_PEER_RUNTIME_CLOSING;
    }
    if (impl->state == PEER_RUNTIME_STATE_CLOSED) {
        return NINLIL_V1_LAB_PEER_RUNTIME_CLOSED;
    }
    if (impl->state != PEER_RUNTIME_STATE_ACTIVE
        || !composition_step_once(impl, 1u)) {
        impl->state = PEER_RUNTIME_STATE_FENCED;
        return NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
    }
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_service(
    ninlil_v1_lab_peer_runtime_t *runtime,
    uint8_t service_slot,
    ninlil_service_t **out_service)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    uint8_t index;

    if (out_service != NULL) {
        *out_service = NULL;
    }
    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC
        || out_service == NULL) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }
    if (impl->state != PEER_RUNTIME_STATE_ACTIVE) {
        return impl->state == PEER_RUNTIME_STATE_FENCED
            ? NINLIL_V1_LAB_PEER_RUNTIME_FENCED
            : NINLIL_V1_LAB_PEER_RUNTIME_WAITING;
    }
    for (index = 0u; index < impl->service_count; ++index) {
        if (impl->service_slots[index] == service_slot
            && impl->services[index] != NULL) {
            *out_service = impl->services[index];
            return NINLIL_V1_LAB_PEER_RUNTIME_OK;
        }
    }
    return NINLIL_V1_LAB_PEER_RUNTIME_SERVICE;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_close_begin(
    ninlil_v1_lab_peer_runtime_t *runtime)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    uint8_t index;

    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }
    if (impl->state == PEER_RUNTIME_STATE_CLOSED) {
        return NINLIL_V1_LAB_PEER_RUNTIME_CLOSED;
    }
    if (impl->state == PEER_RUNTIME_STATE_CLOSING) {
        return NINLIL_V1_LAB_PEER_RUNTIME_CLOSING;
    }
    if (impl->composition == NULL) {
        ninlil_v1_lab_binding_clear(&impl->binding);
        impl->local_endpoint = NULL;
        impl->controller_endpoint = NULL;
        impl->radio = NULL;
        impl->state = PEER_RUNTIME_STATE_CLOSED;
        return NINLIL_V1_LAB_PEER_RUNTIME_OK;
    }
    impl->state = PEER_RUNTIME_STATE_CLOSING;
    for (index = 0u; index < impl->registration_count; ++index) {
        if (impl->registrations[index] != NULL
            && ninlil_fabric_v1_unregister_begin(
                   impl->fabric, impl->registrations[index])
                != NINLIL_FABRIC_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_FABRIC;
        }
        impl->unregister_started[index] = 1u;
    }
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_close_step(
    ninlil_v1_lab_peer_runtime_t *runtime,
    uint32_t *out_done)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);
    uint32_t all_unregistered = 1u;
    uint8_t index;

    if (out_done != NULL) {
        *out_done = 0u;
    }
    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC
        || out_done == NULL) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }
    if (impl->state == PEER_RUNTIME_STATE_CLOSED) {
        *out_done = 1u;
        return NINLIL_V1_LAB_PEER_RUNTIME_OK;
    }
    if (impl->state != PEER_RUNTIME_STATE_CLOSING) {
        return NINLIL_V1_LAB_PEER_RUNTIME_CLOSING;
    }
    for (index = 0u; index < impl->registration_count; ++index) {
        uint32_t done = 0u;

        if (impl->registrations[index] == NULL) {
            continue;
        }
        if (impl->unregister_started[index] == 0u
            || ninlil_fabric_v1_unregister_poll(impl->fabric,
                   impl->registrations[index], &done)
                != NINLIL_FABRIC_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_FABRIC;
        }
        if (done != 0u) {
            impl->registrations[index] = NULL;
        } else {
            all_unregistered = 0u;
        }
    }
    if (all_unregistered == 0u) {
        return composition_step_once(impl, 0u)
            ? NINLIL_V1_LAB_PEER_RUNTIME_CLOSING
            : NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
    }
    if (impl->composition_close_started == 0u) {
        if (ninlil_composition_v1_close_begin(impl->composition)
            != NINLIL_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
        }
        impl->composition_close_started = 1u;
    }
    {
        uint32_t done = 0u;
        if (ninlil_composition_v1_close_poll(
                impl->composition, 64u, &done)
            != NINLIL_OK) {
            return NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
        }
        if (done == 0u) {
            return NINLIL_V1_LAB_PEER_RUNTIME_CLOSING;
        }
    }
    if (ninlil_composition_v1_destroy(impl->composition) != NINLIL_OK) {
        return NINLIL_V1_LAB_PEER_RUNTIME_COMPOSITION;
    }
    impl->composition = NULL;
    impl->runtime = NULL;
    impl->fabric = NULL;
    ninlil_v1_lab_binding_clear(&impl->binding);
    impl->local_endpoint = NULL;
    impl->controller_endpoint = NULL;
    impl->radio = NULL;
    impl->state = PEER_RUNTIME_STATE_CLOSED;
    *out_done = 1u;
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}

ninlil_v1_lab_peer_runtime_status_t ninlil_v1_lab_peer_runtime_clear(
    ninlil_v1_lab_peer_runtime_t *runtime)
{
    ninlil_v1_lab_peer_runtime_impl_t *impl = peer_impl(runtime);

    if (impl == NULL || impl->magic != PEER_RUNTIME_MAGIC
        || (impl->state != PEER_RUNTIME_STATE_PREPARED
            && impl->state != PEER_RUNTIME_STATE_CLOSED)) {
        return NINLIL_V1_LAB_PEER_RUNTIME_INVALID_ARGUMENT;
    }
    secure_clear(runtime, sizeof(*runtime));
    return NINLIL_V1_LAB_PEER_RUNTIME_OK;
}
