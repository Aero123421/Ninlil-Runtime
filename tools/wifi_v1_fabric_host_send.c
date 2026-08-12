/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Real Fabric outer -> Wi-Fi packet-link -> TLS/TCP Host acceptance path.
 *
 * This is a test/tool TU, not an installed API.  It deliberately uses the
 * production-private Fabric and Wi-Fi seams with POSIX SQLite durability.
 */
#include "wifi_v1_fabric_host_send.h"

#include "fabric_private_api.h"
#include "ninlil_posix_sqlite_storage.h"
#include "wifi_fabric_adapter.h"
#include "wifi_nfl1_min.h"

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct host_fabric_clock {
    ninlil_time_sample_t sample;
} host_fabric_clock_t;

typedef struct host_fabric_context {
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *bearer;
    ninlil_bearer_handle_t bearer_handle;
    ninlil_fabric_registration_private_t *registration;
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_wifi_fabric_link_user_t link_user;
    ninlil_wifi_fabric_call_scope_v1_t link_scope;
    ninlil_clock_ops_t clock_ops;
    ninlil_execution_ops_t execution_ops;
    ninlil_fabric_config_v1_t config;
    uint8_t policy_digest[32];
    int active;
} host_fabric_context_t;

typedef struct host_peer_response_tracker {
    uint32_t total_count;
    uint32_t context_count;
} host_peer_response_tracker_t;

static _Alignas(max_align_t)
    uint8_t g_host_fabric_workspace[NINLIL_FABRIC_WORKSPACE_BYTES];

static void id_pattern(ninlil_id128_t *id, uint8_t start)
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(start + (uint8_t)i);
    }
}

static void id_counter(ninlil_id128_t *id, uint8_t domain, uint64_t value)
{
    uint32_t i;
    (void)memset(id->bytes, domain, 8u);
    for (i = 0u; i < 8u; ++i) {
        id->bytes[15u - i] = (uint8_t)(value & 0xffu);
        value >>= 8u;
    }
    id->bytes[0] = domain;
}

static void byte_pattern(uint8_t *dst, uint8_t start, uint32_t length)
{
    uint32_t i;
    for (i = 0u; i < length; ++i) {
        dst[i] = (uint8_t)(start + (uint8_t)i);
    }
}

static ninlil_port_status_t host_clock_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    host_fabric_clock_t *clock = (host_fabric_clock_t *)user;
    if (clock == NULL || out_sample == NULL) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    *out_sample = clock->sample;
    return NINLIL_PORT_OK;
}

static uint64_t host_execution_context(void *user)
{
    (void)user;
    return 1u;
}

static void fill_descriptor(ninlil_fabric_link_descriptor_v1_t *descriptor)
{
    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    id_pattern(&descriptor->instance_id, 0x61u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask =
        NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags =
        NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST
        | NINLIL_FABRIC_CAP_BROADCAST
        | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-fabric-descriptor-v1",
        30u,
        descriptor->descriptor_digest);
    id_pattern(&descriptor->security_profile_id, 0x21u);
    descriptor->security_capability_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-security-binding-v1",
        29u,
        descriptor->security_binding_digest);
    descriptor->attestation_epoch = 1u;
    id_pattern(&descriptor->attestation_clock_epoch_id, 0xA1u);
    descriptor->attestation_expires_at_ms = UINT64_MAX;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-attestation-v1",
        24u,
        descriptor->attestation_digest);
    id_pattern(&descriptor->authenticated_peer_runtime_id, 0x31u);
    id_pattern(&descriptor->attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-attachment-v1",
        23u,
        descriptor->attachment_binding_digest);
    descriptor->maximum_packet_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->maximum_transfer_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->latency_class = 10u;
    descriptor->cost_class = 20u;
    descriptor->reservation_capacity = NINLIL_WIFI_TX_QUEUE_DEPTH;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-config-v1",
        19u,
        descriptor->configuration_digest);
}

static void fill_message(
    ninlil_bearer_message_t *message,
    uint64_t sequence,
    uint64_t now_ms,
    uint8_t payload[4])
{
    static const uint8_t namespace_id[] = { 'h', 'o', 's', 't' };
    static const uint8_t service_id[] = { 'f', 'r', 'a', 'm', 'e' };
    static const uint8_t schema_id[] = { 'v', '1' };
    uint8_t digest[32];

    payload[0] = (uint8_t)(sequence >> 24);
    payload[1] = (uint8_t)(sequence >> 16);
    payload[2] = (uint8_t)(sequence >> 8);
    payload[3] = (uint8_t)sequence;
    (void)memset(message, 0, sizeof(*message));
    message->abi_version = NINLIL_ABI_VERSION;
    message->struct_size = (uint16_t)sizeof(*message);
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    id_counter(&message->transaction_id, 0x10u, sequence);
    id_counter(&message->attempt_id, 0x20u, sequence);
    message->source.abi_version = NINLIL_ABI_VERSION;
    message->source.struct_size = (uint16_t)sizeof(message->source);
    id_pattern(&message->source.runtime_id, 0x30u);
    id_pattern(&message->source.application_instance_id, 0x40u);
    message->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    message->source.local_identity.struct_size =
        (uint16_t)sizeof(message->source.local_identity);
    id_pattern(&message->source.local_identity.device_id, 0x50u);
    id_pattern(&message->source.local_identity.installation_id, 0x60u);
    id_pattern(&message->source.local_identity.site_domain_id, 0x70u);
    message->source.local_identity.binding_epoch = 7u;
    message->source.local_identity.membership_epoch = 9u;
    message->source.local_identity.flags = 7u;
    message->target.abi_version = NINLIL_ABI_VERSION;
    message->target.struct_size = (uint16_t)sizeof(message->target);
    id_pattern(&message->target.target_runtime_id, 0x80u);
    id_pattern(&message->target.target_application_instance_id, 0x90u);
    id_pattern(&message->target.device_id, 0xA0u);
    id_pattern(&message->target.installation_id, 0xB0u);
    id_pattern(&message->target.site_domain_id, 0xC0u);
    message->target.binding_epoch = 11u;
    message->target.membership_epoch = 13u;
    message->target.flags = 7u;
    message->service.abi_version = NINLIL_ABI_VERSION;
    message->service.struct_size = (uint16_t)sizeof(message->service);
    message->service.namespace_id.length = (uint8_t)sizeof(namespace_id);
    (void)memcpy(
        message->service.namespace_id.bytes,
        namespace_id,
        sizeof(namespace_id));
    message->service.service_id.length = (uint8_t)sizeof(service_id);
    (void)memcpy(
        message->service.service_id.bytes, service_id, sizeof(service_id));
    message->service.schema_id.length = (uint8_t)sizeof(schema_id);
    (void)memcpy(
        message->service.schema_id.bytes, schema_id, sizeof(schema_id));
    message->service.descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"wifi-host-service-v1", 20u, digest);
    message->service.descriptor_digest.algorithm = 1u;
    (void)memcpy(message->service.descriptor_digest.bytes, digest, 32u);
    message->service.schema_major = 1u;
    message->service.schema_minor = 0u;
    message->service.family = 2u;
    ninlil_fabric_private_sha256(payload, 4u, digest);
    message->content_digest.algorithm = 1u;
    (void)memcpy(message->content_digest.bytes, digest, 32u);
    message->generation = sequence;
    id_pattern(&message->deadline_clock_epoch_id, 0xA1u);
    message->absolute_effect_deadline_ms = now_ms + 60000u;
    message->evidence_grace_ms = 5000u;
    message->required_evidence = 3u;
    message->payload.data = payload;
    message->payload.length = 4u;
}

static int install_policy_and_authority(
    host_fabric_context_t *context, const ninlil_bearer_message_t *message)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t binding;
    ninlil_fabric_path_policy_v1_t snapshot;
    uint8_t service_digest[32];

    ninlil_fabric_private_nfl1_service_identity_digest(
        message->service.namespace_id.bytes,
        message->service.namespace_id.length,
        message->service.service_id.bytes,
        message->service.service_id.length,
        message->service.schema_id.bytes,
        message->service.schema_id.length,
        message->service.descriptor_revision,
        message->service.descriptor_digest.bytes,
        message->service.schema_major,
        message->service.schema_minor,
        message->service.family,
        service_digest);

    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    id_pattern(&policy.policy_id, 0x71u);
    policy.revision = 3u;
    (void)memcpy(policy.service_identity_digest, service_digest, 32u);
    policy.family = 2u;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    policy.required_security_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 50u;
    policy.maximum_cost_class = 50u;
    policy.minimum_packet_bytes = 587u;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 100u;
    policy.candidate_count = 1u;
    policy.candidates[0].instance_id = context->descriptor.instance_id;
    policy.candidates[0].rank = 10u;
    policy.candidates[0].reservation_units = 1u;
    if (ninlil_fabric_private_policy_put_v1(context->fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    if (ninlil_fabric_private_policy_snapshot_v1(
            context->fabric, &policy.policy_id, policy.revision, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    (void)memcpy(
        context->policy_digest,
        snapshot.canonical_digest_zero_on_input,
        32u);

    (void)memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    id_pattern(&binding.binding_id, 0xB8u);
    (void)memcpy(binding.service_identity_digest, service_digest, 32u);
    binding.family = 2u;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    id_pattern(&binding.endpoint_runtime_id, 0x80u);
    id_pattern(&binding.target_runtime_id, 0x80u);
    id_pattern(&binding.target_application_id, 0x90u);
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    (void)memcpy(binding.policy_digest, context->policy_digest, 32u);
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    id_pattern(&binding.authority_id, 0xD0u);
    binding.authority_term = 17u;
    binding.assignment_epoch = 19u;
    id_pattern(&binding.owner_scope_id, 0x81u);
    byte_pattern(binding.owner_tuple_canonical, 0x81u, 200u);
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    id_pattern(&binding.authority_clock_epoch_id, 0xA1u);
    binding.lease_expires_at_ms = UINT64_MAX;
    binding.assignment_revision = 11u;
    return ninlil_fabric_private_authority_put_v1(context->fabric, &binding)
            == NINLIL_FABRIC_PRIVATE_OK
        ? 0
        : -1;
}

static int snapshot_policy_digest(host_fabric_context_t *context)
{
    ninlil_fabric_path_policy_v1_t snapshot;
    ninlil_id128_t policy_id;
    id_pattern(&policy_id, 0x71u);
    if (ninlil_fabric_private_policy_snapshot_v1(
            context->fabric, &policy_id, 3u, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    (void)memcpy(
        context->policy_digest,
        snapshot.canonical_digest_zero_on_input,
        32u);
    return 0;
}

static int fabric_context_boot(
    host_fabric_context_t *context,
    ninlil_wifi_session_t *session,
    ninlil_posix_sqlite_storage_t *storage,
    host_fabric_clock_t *clock,
    int fresh)
{
    ninlil_id128_t runtime_id;
    ninlil_bearer_message_t seed;
    uint8_t seed_payload[4];

    (void)memset(context, 0, sizeof(*context));
    (void)memset(g_host_fabric_workspace, 0, sizeof(g_host_fabric_workspace));
    context->clock_ops.abi_version = NINLIL_ABI_VERSION;
    context->clock_ops.struct_size = (uint16_t)sizeof(context->clock_ops);
    context->clock_ops.user = clock;
    context->clock_ops.now = host_clock_now;
    context->execution_ops.abi_version = NINLIL_ABI_VERSION;
    context->execution_ops.struct_size =
        (uint16_t)sizeof(context->execution_ops);
    context->execution_ops.current_context_id = host_execution_context;
    context->config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    context->config.struct_size = (uint16_t)sizeof(context->config);
    context->config.profile_id = NINLIL_FABRIC_PROFILE_1;
    context->config.storage = ninlil_posix_sqlite_storage_ops(storage);
    context->config.clock = &context->clock_ops;
    context->config.execution = &context->execution_ops;
    {
        ninlil_fabric_private_status_t status =
            ninlil_fabric_private_create_v1(
                &context->config,
                g_host_fabric_workspace,
                (uint32_t)sizeof(g_host_fabric_workspace),
                &context->fabric);
        if (status != NINLIL_FABRIC_PRIVATE_OK) {
            (void)fprintf(
                stderr, "fabric context create failed status=%u\n",
                (unsigned)status);
            return -1;
        }
    }
    context->active = 1;
    if (ninlil_fabric_private_bearer_ops_v1(
            context->fabric, &context->bearer)
        != NINLIL_FABRIC_PRIVATE_OK) {
        (void)fprintf(stderr, "fabric context bearer ops failed\n");
        return -1;
    }

    fill_descriptor(&context->descriptor);
    context->link_user.session = session;
    if (ninlil_wifi_fabric_bind_trusted_clock(
            &context->link_user, &clock->sample)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "fabric context clock bind failed\n");
        return -1;
    }
    ninlil_wifi_fabric_packet_link_ops_init(
        &context->link_ops, &context->link_user);
    if (!ninlil_wifi_fabric_packet_link_authority_prepare(
            &context->link_user, context->fabric)) {
        (void)fprintf(stderr, "fabric context authority prepare failed\n");
        return -1;
    }
    ninlil_wifi_fabric_packet_link_ops_scoped_init(
        &context->link_ops,
        &context->link_user,
        &context->link_scope,
        context->fabric);
    if (ninlil_fabric_private_register_link_v1(
            context->fabric,
            &context->descriptor,
            &context->link_ops,
            &context->registration)
        != NINLIL_FABRIC_PRIVATE_OK) {
        (void)fprintf(stderr, "fabric context register link failed\n");
        (void)ninlil_wifi_fabric_packet_link_authority_unbind(
            &context->link_user, context->fabric);
        return -1;
    }
    if (!ninlil_wifi_fabric_packet_link_authority_activate(
            &context->link_user, context->fabric)) {
        (void)fprintf(stderr, "fabric context authority activate failed\n");
        return -1;
    }
    fill_message(&seed, 1u, clock->sample.now_ms, seed_payload);
    if (fresh != 0) {
        if (install_policy_and_authority(context, &seed) != 0) {
            (void)fprintf(stderr, "fabric context policy install failed\n");
            return -1;
        }
    } else if (snapshot_policy_digest(context) != 0) {
        (void)fprintf(stderr, "fabric context policy snapshot failed\n");
        return -1;
    }

    id_pattern(&runtime_id, 0x30u);
    if (context->bearer->open(
            context->bearer->user,
            &runtime_id,
            NINLIL_ROLE_ENDPOINT,
            &context->bearer_handle)
        != NINLIL_BEARER_OK) {
        (void)fprintf(stderr, "fabric context bearer open failed\n");
        return -1;
    }
    context->active = 1;
    return 0;
}

static int fabric_context_shutdown(host_fabric_context_t *context)
{
    uint32_t done = 0u;
    uint32_t spins;
    ninlil_fabric_private_t *fabric_cookie;
    if (context == NULL || context->fabric == NULL) {
        return 0;
    }
    if (context->bearer != NULL && context->bearer_handle != NULL) {
        context->bearer->close(
            context->bearer->user, context->bearer_handle);
        context->bearer_handle = NULL;
    }
    fabric_cookie = context->fabric;
    if (!ninlil_wifi_fabric_packet_link_authority_drain(
            &context->link_user, fabric_cookie)) {
        return -1;
    }
    if (ninlil_fabric_private_close_begin_v1(context->fabric)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    for (spins = 0u; spins < 1024u && done == 0u; ++spins) {
        uint32_t work = 0u;
        if (ninlil_fabric_private_step_v1(context->fabric, 64u, &work)
                != NINLIL_FABRIC_PRIVATE_OK
            || ninlil_fabric_private_close_poll_v1(context->fabric, &done)
                != NINLIL_FABRIC_PRIVATE_OK) {
            return -1;
        }
    }
    if (done == 0u
        || ninlil_fabric_private_destroy_v1(context->fabric)
            != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    if (!ninlil_wifi_fabric_packet_link_authority_unbind(
            &context->link_user, fabric_cookie)) {
        return -1;
    }
    context->fabric = NULL;
    context->active = 0;
    return 0;
}

static int provider_released(const ninlil_wifi_fabric_link_user_t *user)
{
    uint32_t i;
    if (user->permit_live_count != 0u) {
        return 0;
    }
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        if (user->send_slots[i].in_use != 0u) {
            return 0;
        }
    }
    for (i = 0u; i < NINLIL_WIFI_FABRIC_PERMIT_LEDGER; ++i) {
        if (user->permit_ledger[i].state
            != NINLIL_WIFI_FABRIC_PERMIT_ST_EMPTY) {
            return 0;
        }
    }
    return 1;
}

/*
 * One request is followed by one real NWB1/TLS response before the next
 * request starts. The packet-link transcript advances only after NWB1 has
 * rejected gaps/duplicates and exposed the exact NFL1 digest.
 */
static int wait_for_peer_response(
    host_fabric_context_t *context,
    host_peer_response_tracker_t *tracker,
    uint32_t maximum_count)
{
    uint8_t expected_payload[587];
    uint8_t expected_digest[32];
    size_t expected_length = 0u;
    uint64_t expected_context_count;
    uint32_t spins;

    if (context == NULL || tracker == NULL
        || tracker->total_count >= maximum_count
        || ninlil_wifi_nfl1_min_encode(
               expected_payload,
               sizeof(expected_payload),
               &expected_length,
               100000u + tracker->total_count)
            != NINLIL_WIFI_OK) {
        return -1;
    }
    ninlil_fabric_private_sha256(
        expected_payload, (uint32_t)expected_length, expected_digest);
    expected_context_count = (uint64_t)tracker->context_count + 1u;

    for (spins = 0u; spins < 200000u; ++spins) {
        uint32_t work = 0u;
        ninlil_bearer_message_t inbound;
        ninlil_bearer_status_t receive_status;
        if (ninlil_fabric_private_step_v1(context->fabric, 64u, &work)
            != NINLIL_FABRIC_PRIVATE_OK) {
            return -1;
        }
        /*
         * A structurally valid liveness response is not required to match an
         * application authority. If it is nevertheless published, release its
         * exact-one outer loan immediately so ingress capacity cannot mask the
         * transcript assertion.
         */
        do {
            (void)memset(&inbound, 0, sizeof(inbound));
            receive_status = context->bearer->receive_next(
                context->bearer->user,
                context->bearer_handle,
                &inbound);
            if (receive_status == NINLIL_BEARER_OK) {
                context->bearer->release_received(
                    context->bearer->user,
                    context->bearer_handle,
                    &inbound);
            }
        } while (receive_status == NINLIL_BEARER_OK);
        if (receive_status != NINLIL_BEARER_EMPTY
            && receive_status != NINLIL_BEARER_WOULD_BLOCK) {
            return -1;
        }
        if (context->link_user.accepted_receive_count
            > expected_context_count) {
            return -1;
        }
        if (context->link_user.accepted_receive_count
            == expected_context_count) {
            if (context->link_user.last_receive_sequence
                    != tracker->total_count
                || context->link_user.last_receive_length
                    != (uint32_t)expected_length
                || memcmp(
                       context->link_user.last_receive_digest,
                       expected_digest,
                       sizeof(expected_digest))
                    != 0) {
                (void)fprintf(
                    stderr,
                    "Fabric peer response mismatch count=%u sequence=%u "
                    "length=%u expected=%zu\n",
                    tracker->total_count,
                    context->link_user.last_receive_sequence,
                    context->link_user.last_receive_length,
                    expected_length);
                return -1;
            }
            tracker->total_count += 1u;
            tracker->context_count += 1u;
            return 0;
        }
        usleep(50u);
    }
    (void)fprintf(
        stderr,
        "Fabric peer response incomplete total=%u context=%u\n",
        tracker->total_count,
        tracker->context_count);
    return -1;
}

static int foundation_digest_for(
    const host_fabric_context_t *context,
    const ninlil_bearer_message_t *message,
    uint64_t path_selection_epoch,
    uint8_t out_digest[32])
{
    ninlil_id128_t authority_id;
    ninlil_id128_t policy_id;
    uint8_t packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t packet_length = 0u;
    id_pattern(&authority_id, 0xD0u);
    id_pattern(&policy_id, 0x71u);
    if (ninlil_fabric_private_enrich_nfl1_v1(
            message,
            authority_id.bytes,
            17u,
            19u,
            policy_id.bytes,
            3u,
            context->policy_digest,
            context->descriptor.instance_id.bytes,
            path_selection_epoch,
            packet,
            (uint32_t)sizeof(packet),
            &packet_length)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return -1;
    }
    ninlil_fabric_private_nfl1_foundation_message_digest(
        packet, packet_length, out_digest);
    return 0;
}

static int drive_terminal_release(host_fabric_context_t *context)
{
    uint32_t spins;
    for (spins = 0u; spins < 200000u; ++spins) {
        uint32_t work = 0u;
        ninlil_fabric_private_status_t step_status =
            ninlil_fabric_private_step_v1(context->fabric, 64u, &work);
        if (step_status != NINLIL_FABRIC_PRIVATE_OK) {
            (void)fprintf(
                stderr,
                "fabric step failed status=%u spins=%u\n",
                (unsigned)step_status,
                spins);
            return -1;
        }
        if (provider_released(&context->link_user) != 0) {
            return 0;
        }
        if ((spins & 31u) == 31u) {
            usleep(50u);
        }
    }
    return -1;
}

static int send_one(
    host_fabric_context_t *context,
    host_fabric_clock_t *clock,
    uint64_t sequence,
    uint64_t path_selection_epoch,
    ninlil_tx_permit_t *out_first_permit)
{
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint8_t payload[4];
    uint8_t foundation_digest[32];
    uint32_t response_slot;
    uint64_t accepts_before = context->link_user.accepted_send_count;

    fill_message(&message, sequence, clock->sample.now_ms, payload);
    (void)memset(&permit, 0, sizeof(permit));
    permit.abi_version = NINLIL_ABI_VERSION;
    permit.struct_size = (uint16_t)sizeof(permit);
    id_counter(&permit.permit_id, 0xE0u, sequence);
    permit.attempt_id = message.attempt_id;
    permit.clock_epoch_id = clock->sample.clock_epoch_id;
    permit.expires_at_ms = clock->sample.now_ms + 60000u;
    if (foundation_digest_for(
            context, &message, path_selection_epoch, foundation_digest)
        != 0) {
        (void)fprintf(stderr, "fabric foundation encode failed\n");
        return -1;
    }
    if (ninlil_wifi_fabric_bind_trusted_clock(
            &context->link_user, &clock->sample)
        != NINLIL_WIFI_OK) {
        (void)fprintf(stderr, "wifi trusted clock bind failed\n");
        return -1;
    }
    (void)memset(&result, 0, sizeof(result));
    {
        ninlil_bearer_status_t send_status = context->bearer->send(
            context->bearer->user,
            context->bearer_handle,
            &permit,
            &message,
            &result);
        if (send_status != NINLIL_BEARER_OK
        || result.kind != NINLIL_BEARER_SEND_ACCEPTED
        || context->link_user.accepted_send_count != accepts_before + 1u) {
            ninlil_fabric_link_descriptor_v1_t descriptor_snapshot;
            ninlil_fabric_link_state_v1_t state_snapshot;
            ninlil_fabric_link_metrics_v1_t metrics_snapshot;
            ninlil_fabric_private_status_t link_snapshot_status;
            ninlil_fabric_private_status_t metrics_status;
            (void)memset(
                &descriptor_snapshot, 0, sizeof(descriptor_snapshot));
            (void)memset(&state_snapshot, 0, sizeof(state_snapshot));
            (void)memset(&metrics_snapshot, 0, sizeof(metrics_snapshot));
            link_snapshot_status = ninlil_fabric_private_link_snapshot_v1(
                context->fabric,
                &context->descriptor.instance_id,
                &descriptor_snapshot,
                &state_snapshot);
            metrics_status = ninlil_fabric_private_metrics_snapshot_v1(
                context->fabric,
                &context->descriptor.instance_id,
                &metrics_snapshot);
            (void)fprintf(
                stderr,
                "fabric bearer send rejected status=%u kind=%u "
                "accepts=%llu/%llu phase=%u session_epoch=%llu "
                "link_snapshot=%u avail=%u link_epoch=%llu until=%llu "
                "metrics=%u retained=%u queued=%u\n",
                (unsigned)send_status,
                (unsigned)result.kind,
                (unsigned long long)context->link_user.accepted_send_count,
                (unsigned long long)(accepts_before + 1u),
                (unsigned)context->link_user.session->phase,
                (unsigned long long)
                    context->link_user.session->availability_epoch,
                (unsigned)link_snapshot_status,
                (unsigned)state_snapshot.available,
                (unsigned long long)state_snapshot.availability_epoch,
                (unsigned long long)state_snapshot.available_until_ms,
                (unsigned)metrics_status,
                (unsigned)metrics_snapshot.retained_tokens,
                (unsigned)metrics_snapshot.queued_items);
            return -1;
        }
    }
    if (out_first_permit != NULL) {
        *out_first_permit = permit;
    }
    if (drive_terminal_release(context) != 0) {
        (void)fprintf(
            stderr,
            "fabric completion/release failed phase=%u live=%u\n",
            (unsigned)context->link_user.session->phase,
            (unsigned)context->link_user.permit_live_count);
        return -1;
    }
    response_slot = ninlil_fabric_private_nfl1_response_slot(
        message.kind,
        message.receipt_stage,
        message.disposition,
        message.cancel_kind);
    {
        ninlil_fabric_private_status_t release_status =
            ninlil_fabric_private_dispatch_release_v1(
            context->fabric,
            &message.transaction_id,
            &message.attempt_id,
            message.kind,
            response_slot,
            foundation_digest,
            sequence);
        if (release_status != NINLIL_FABRIC_PRIVATE_OK) {
            (void)fprintf(
                stderr,
                "fabric dispatch release failed status=%u\n",
                (unsigned)release_status);
            return -1;
        }
    }
    return 0;
}

static int replay_is_denied(
    host_fabric_context_t *context,
    host_fabric_clock_t *clock,
    const ninlil_tx_permit_t *consumed_permit,
    uint64_t sequence)
{
    ninlil_bearer_message_t message;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t result;
    uint8_t payload[4];
    uint64_t accepts_before = context->link_user.accepted_send_count;

    fill_message(&message, sequence, clock->sample.now_ms, payload);
    permit = *consumed_permit;
    permit.attempt_id = message.attempt_id;
    /*
     * TxGate MUST NOT reissue an {epoch, permit_id} pair. Exercise the exact
     * originally issued permit: while its FBA1 exists the pair denies replay;
     * after bounded GC the original expiry itself remains fail-closed.
     */
    (void)memset(&result, 0, sizeof(result));
    if (context->bearer->send(
            context->bearer->user,
            context->bearer_handle,
            &permit,
            &message,
            &result)
            != NINLIL_BEARER_DENIED
        || context->link_user.accepted_send_count != accepts_before
        || provider_released(&context->link_user) == 0) {
        return -1;
    }
    return 0;
}

static int make_temp_path(char *out, size_t out_size)
{
    const char *tmpdir = getenv("TMPDIR");
    int written;
    int fd;
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    written = snprintf(
        out, out_size, "%s/ninlil-wifi-fabric-XXXXXX", tmpdir);
    if (written <= 0 || (size_t)written >= out_size) {
        return -1;
    }
    fd = mkstemp(out);
    if (fd < 0) {
        return -1;
    }
    if (close(fd) != 0) {
        (void)remove(out);
        return -1;
    }
    return 0;
}

static int authority_lock_path(
    const char *path, char *out, size_t out_size)
{
    struct stat st;
    char *canonical;
    char *slash;
    size_t parent_length;
    int written;
    if (stat(path, &st) != 0) {
        return 0;
    }
    canonical = realpath(path, NULL);
    if (canonical == NULL) {
        return 0;
    }
    slash = strrchr(canonical, '/');
    if (slash == NULL) {
        free(canonical);
        return 0;
    }
    parent_length = slash == canonical ? 1u : (size_t)(slash - canonical);
    written = snprintf(
        out,
        out_size,
        "%.*s/.ninlil-sqlite-%llx-%llx.lock",
        (int)parent_length,
        canonical,
        (unsigned long long)st.st_dev,
        (unsigned long long)st.st_ino);
    free(canonical);
    return written > 0 && (size_t)written < out_size;
}

static void remove_db_artifacts(const char *path)
{
    char suffix_path[768];
    char lock_path[768];
    int have_lock = authority_lock_path(path, lock_path, sizeof(lock_path));
    (void)snprintf(suffix_path, sizeof(suffix_path), "%s-wal", path);
    (void)remove(suffix_path);
    (void)snprintf(suffix_path, sizeof(suffix_path), "%s-shm", path);
    (void)remove(suffix_path);
    (void)snprintf(suffix_path, sizeof(suffix_path), "%s-journal", path);
    (void)remove(suffix_path);
    (void)remove(path);
    if (have_lock != 0) {
        (void)remove(lock_path);
    }
}

int ninlil_wifi_host_fabric_send_frames(
    ninlil_wifi_session_t *session,
    uint32_t frames,
    uint32_t slow_ms,
    uint32_t start_id,
    int require_peer_response_each)
{
    host_fabric_context_t context;
    host_fabric_clock_t clock;
    ninlil_posix_sqlite_storage_config_t storage_config;
    ninlil_posix_sqlite_storage_t *storage = NULL;
    ninlil_tx_permit_t first_permit;
    char database_path[512];
    uint32_t i;
    uint32_t restart_at;
    uint64_t path_selection_epoch = 1u;
    host_peer_response_tracker_t response_tracker;
    int rc = -1;

    (void)memset(&context, 0, sizeof(context));
    (void)memset(&response_tracker, 0, sizeof(response_tracker));
    if (session == NULL || frames == 0u
        || session->phase != NINLIL_WIFI_PHASE_ATTACHED
        || make_temp_path(database_path, sizeof(database_path)) != 0) {
        return -1;
    }
    (void)memset(&clock, 0, sizeof(clock));
    clock.sample.abi_version = NINLIL_ABI_VERSION;
    clock.sample.struct_size = (uint16_t)sizeof(clock.sample);
    id_pattern(&clock.sample.clock_epoch_id, 0xA1u);
    clock.sample.now_ms = 100000u;
    clock.sample.trust = NINLIL_CLOCK_TRUSTED;
    (void)memset(&storage_config, 0, sizeof(storage_config));
    storage_config.database_path = database_path;
    storage_config.busy_timeout_ms = 1000u;
    storage_config.max_entries_per_namespace =
        (uint64_t)frames * 2u + 128u;
    storage_config.max_bytes_per_namespace =
        (uint64_t)frames * 2048u + 1048576u;
    storage_config.max_handles = 16u;
    storage_config.max_transactions = 16u;
    storage_config.max_iterators = 16u;
    storage = ninlil_posix_sqlite_storage_create(&storage_config);
    if (storage == NULL
        || fabric_context_boot(&context, session, storage, &clock, 1) != 0) {
        goto cleanup;
    }

    restart_at = frames > 1u ? frames / 2u : UINT32_MAX;
    for (i = 0u; i < frames; ++i) {
        uint64_t sequence = (uint64_t)start_id + (uint64_t)i;
        if (send_one(
                &context,
                &clock,
                sequence,
                path_selection_epoch,
                i == 0u ? &first_permit : NULL)
            != 0) {
            (void)fprintf(
                stderr,
                "fabric host send failed frame=%u clock=%llu epoch=%llu\n",
                i,
                (unsigned long long)clock.sample.now_ms,
                (unsigned long long)path_selection_epoch);
            goto cleanup;
        }
        if (require_peer_response_each != 0
            && wait_for_peer_response(
                   &context, &response_tracker, frames)
                != 0) {
            (void)fprintf(
                stderr,
                "Fabric peer response validation failed after frame=%u\n",
                i);
            goto cleanup;
        }
        path_selection_epoch += 1u;
        clock.sample.now_ms += NINLIL_FABRIC_RETRY_LIFETIME_MS + 1u;
        if (i == 0u
            && replay_is_denied(
                   &context,
                   &clock,
                   &first_permit,
                   (uint64_t)start_id + (uint64_t)frames + 1u)
                != 0) {
            (void)fprintf(stderr, "fabric live replay was not denied\n");
            goto cleanup;
        }
        if (slow_ms > 0u && (i % 100u) == 0u) {
            usleep(slow_ms * 1000u);
        }
        if (i + 1u == restart_at) {
            /*
             * Crash semantics: invalidate all storage leases without Fabric
             * close/destroy, drop volatile workspace/link state, then reopen
             * the same database. DRAINED FBA1 carries the co-located durable
             * one-shot permit claim across the restart.
             */
            ninlil_posix_sqlite_storage_simulate_crash(storage);
            ninlil_posix_sqlite_storage_destroy(storage);
            storage = NULL;
            (void)memset(&context, 0, sizeof(context));
            response_tracker.context_count = 0u;
            storage = ninlil_posix_sqlite_storage_create(&storage_config);
            if (storage == NULL
                || fabric_context_boot(
                       &context, session, storage, &clock, 0)
                    != 0
                || replay_is_denied(
                       &context,
                       &clock,
                       &first_permit,
                       (uint64_t)start_id + (uint64_t)frames + 2u)
                    != 0) {
                (void)fprintf(
                    stderr, "fabric crash/reopen replay authority failed\n");
                goto cleanup;
            }
        }
    }
    if (provider_released(&context.link_user) == 0) {
        goto cleanup;
    }
    (void)printf(
        "wifi_v1_host_e2e_driver: Fabric start_send/TLS "
        "completion/release frames=%u responses=%u exactly-once "
        "replay-denied=live+restart\n",
        frames,
        response_tracker.total_count);
    rc = 0;

cleanup:
    if (context.active != 0 && fabric_context_shutdown(&context) != 0) {
        rc = -1;
    }
    if (storage != NULL) {
        ninlil_posix_sqlite_storage_destroy(storage);
    }
    remove_db_artifacts(database_path);
    return rc;
}
