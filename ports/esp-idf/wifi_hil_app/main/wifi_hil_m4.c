/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_hil_m4.h"

#include <string.h>

#define NINLIL_WIFI_HIL_M4_NAMESPACE "wifi-m4"

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0u;
    size_t i;
    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < length; ++i) {
        aggregate |= bytes[i];
    }
    return aggregate == 0u;
}

static int persist_records(
    ninlil_wifi_hil_m4_t *carrier,
    const uint8_t peer_session_id[16],
    uint64_t trusted_now_ms)
{
    ninlil_wifi_m4_membership_lease_t lease;
    const ninlil_wifi_hil_provision_t *provision = carrier->provision;
    (void)memset(&lease, 0, sizeof(lease));
    /*
     * The M4 durable membership record is capability-scoped: its member field
     * is the exporter-derived peer-session ID, not a caller-asserted runtime.
     */
    (void)memcpy(lease.member_runtime_id, peer_session_id, 16u);
    lease.lease_not_before_ms = trusted_now_ms;
    lease.lease_not_after_ms = trusted_now_ms + UINT64_C(86400000);
    (void)memcpy(
        lease.authority_id,
        provision->session.tls_identity.local_leaf.authority_id,
        16u);
    (void)memcpy(
        lease.binding_digest,
        provision->session.tls_identity.local_leaf
            .authorized_attachment_binding_digest,
        32u);
    if (ninlil_wifi_m4_membership_store_full(
            carrier->storage,
            carrier->storage->user,
            NINLIL_WIFI_HIL_M4_NAMESPACE,
            &lease)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_credential_store_full(
               carrier->storage,
               carrier->storage->user,
               NINLIL_WIFI_HIL_M4_NAMESPACE,
               provision->credential_candidate_digest,
               provision->adapter_config.configuration_revision)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_attachment_store_full(
               carrier->storage,
               carrier->storage->user,
               NINLIL_WIFI_HIL_M4_NAMESPACE,
               peer_session_id,
               provision->session.tls_identity.local_leaf.authority_id,
               provision->session.tls_identity.local_leaf
                   .authorized_attachment_binding_digest,
               provision->credential_candidate_digest,
               provision->session.expected_fabric_descriptor)
            != NINLIL_WIFI_OK) {
        return 0;
    }
    (void)memcpy(
        carrier->persisted_peer_session_id, peer_session_id, 16u);
    carrier->records_current = 1u;
    return 1;
}

static void fill_descriptor(
    const ninlil_wifi_hil_m4_t *carrier,
    uint64_t trusted_now_ms,
    ninlil_fabric_link_descriptor_v1_t *descriptor)
{
    const ninlil_wifi_hil_provision_t *provision = carrier->provision;
    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = 1u;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    descriptor->instance_id = provision->adapter_config.instance_id;
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    descriptor->descriptor_revision =
        provision->adapter_config.configuration_revision;
    (void)memcpy(
        descriptor->descriptor_digest,
        provision->session.expected_fabric_descriptor,
        32u);
    (void)memcpy(
        descriptor->security_profile_id.bytes,
        provision->registry_epoch_id,
        16u);
    descriptor->security_capability_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    (void)memcpy(
        descriptor->security_binding_digest,
        provision->session.tls_identity.local_leaf
            .authorized_attachment_binding_digest,
        32u);
    descriptor->attestation_epoch =
        provision->adapter_config.configuration_revision;
    /*
     * Adapter validation replaces this boot-local clock epoch below through
     * the clock sample supplied to poll_full. The carrier copies it from the
     * caller-owned clock after the durable FULL evidence is loaded.
     */
    descriptor->attestation_expires_at_ms =
        trusted_now_ms + UINT64_C(60000);
    (void)memcpy(
        descriptor->attestation_digest,
        provision->session.expected_fabric_descriptor,
        32u);
    descriptor->authenticated_peer_runtime_id =
        provision->adapter_config.expected_peer_runtime_id;
    (void)memcpy(
        descriptor->attachment_authority_id.bytes,
        provision->session.tls_identity.local_leaf.authority_id,
        16u);
    (void)memcpy(
        descriptor->attachment_binding_digest,
        provision->session.tls_identity.local_leaf
            .authorized_attachment_binding_digest,
        32u);
    descriptor->maximum_packet_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->maximum_transfer_bytes = NINLIL_WIFI_NWB1_PAYLOAD_MAX;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->reservation_capacity = 1u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision =
        provision->adapter_config.configuration_revision;
    (void)memcpy(
        descriptor->configuration_digest,
        provision->adapter_config.configuration_digest,
        32u);
}

static wifi_private_adapter_status_v1_t poll_full(
    void *user,
    const uint8_t peer_session_id[16],
    uint64_t trusted_now_ms,
    ninlil_wifi_m4_full_evidence_t *out_evidence,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor)
{
    ninlil_wifi_hil_m4_t *carrier = (ninlil_wifi_hil_m4_t *)user;
    ninlil_wifi_m4_fabric_registry_t registry;
    ninlil_time_sample_t now;
    if (carrier == NULL || carrier->storage == NULL
        || carrier->provision == NULL || peer_session_id == NULL
        || bytes_zero(peer_session_id, 16u) || trusted_now_ms == 0u
        || out_evidence == NULL || out_descriptor == NULL) {
        return WIFI_PRIVATE_INVALID_ARGUMENT;
    }
    if (!carrier->records_current
        || memcmp(
               carrier->persisted_peer_session_id,
               peer_session_id,
               16u)
            != 0) {
        if (!persist_records(carrier, peer_session_id, trusted_now_ms)) {
            return WIFI_PRIVATE_STORAGE;
        }
    }
    if (ninlil_wifi_m4_evidence_reset(&carrier->owner, out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_membership_load_classify(
               &carrier->owner,
               carrier->storage,
               carrier->storage->user,
               NINLIL_WIFI_HIL_M4_NAMESPACE,
               trusted_now_ms,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_credential_load_classify(
               &carrier->owner,
               carrier->storage,
               carrier->storage->user,
               NINLIL_WIFI_HIL_M4_NAMESPACE,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_attachment_load_classify(
               &carrier->owner,
               carrier->storage,
               carrier->storage->user,
               NINLIL_WIFI_HIL_M4_NAMESPACE,
               peer_session_id,
               out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_fabric_registry_bind(
               &registry,
               carrier->provision->session.expected_fabric_descriptor,
               carrier->provision->session.tls_identity.local_leaf
                   .authority_id,
               carrier->provision->registry_epoch_id)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_apply_fabric_registry(
               out_evidence, &registry)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_mark_session_authority(out_evidence)
            != NINLIL_WIFI_OK
        || ninlil_wifi_m4_evidence_ready_for_attach(out_evidence)
            != NINLIL_WIFI_OK) {
        ninlil_wifi_m4_evidence_consume(out_evidence);
        return WIFI_PRIVATE_DENIED;
    }
    fill_descriptor(carrier, trusted_now_ms, out_descriptor);
    (void)memset(&now, 0, sizeof(now));
    now.abi_version = NINLIL_ABI_VERSION;
    now.struct_size = (uint16_t)sizeof(now);
    if (carrier->provision->adapter_config.clock == NULL
        || carrier->provision->adapter_config.clock->now(
               carrier->provision->adapter_config.clock->user, &now)
            != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED
        || now.now_ms < trusted_now_ms
        || bytes_zero(now.clock_epoch_id.bytes, 16u)) {
        ninlil_wifi_m4_evidence_consume(out_evidence);
        (void)memset(out_descriptor, 0, sizeof(*out_descriptor));
        return WIFI_PRIVATE_DENIED;
    }
    (void)memcpy(
        out_descriptor->attestation_clock_epoch_id.bytes,
        now.clock_epoch_id.bytes,
        16u);
    return WIFI_PRIVATE_OK;
}

static void cancel(void *user)
{
    ninlil_wifi_hil_m4_t *carrier = (ninlil_wifi_hil_m4_t *)user;
    if (carrier != NULL) {
        (void)ninlil_wifi_m4_owner_restart(&carrier->owner);
        carrier->records_current = 0u;
        (void)memset(
            carrier->persisted_peer_session_id,
            0,
            sizeof(carrier->persisted_peer_session_id));
    }
}

int ninlil_wifi_hil_m4_init(
    ninlil_wifi_hil_m4_t *carrier,
    const ninlil_storage_ops_t *storage,
    const ninlil_wifi_hil_provision_t *provision)
{
    if (carrier == NULL || storage == NULL || provision == NULL) {
        return 1;
    }
    (void)memset(carrier, 0, sizeof(*carrier));
    ninlil_wifi_m4_owner_init(&carrier->owner);
    carrier->storage = storage;
    carrier->provision = provision;
    carrier->ops.api_version = NINLIL_WIFI_PRIVATE_API_VERSION;
    carrier->ops.struct_size = (uint16_t)sizeof(carrier->ops);
    carrier->ops.user = carrier;
    carrier->ops.poll_full = poll_full;
    carrier->ops.cancel = cancel;
    return 0;
}

const wifi_m4_attachment_carrier_ops_v1_t *ninlil_wifi_hil_m4_ops(
    ninlil_wifi_hil_m4_t *carrier)
{
    return carrier == NULL ? NULL : &carrier->ops;
}
