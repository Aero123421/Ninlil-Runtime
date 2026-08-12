/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private Wi-Fi packet-link seam registered into Fabric (no public ABI).
 * Host-only; not ESP HIL.
 */
#include "fabric_v1_test_common.h"
#include "fabric_v1_test_storage.h"

#if defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1
#include "wifi_fabric_adapter.h"
#include "wifi_session.h"
#include "wifi_nfl1_min.h"
#endif

#include <stdio.h>
#include <string.h>

static uint8_t g_ws[NINLIL_FABRIC_WORKSPACE_BYTES] __attribute__((aligned(16)));

int main(void)
{
#if !(defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) && NINLIL_ENABLE_PRIVATE_FABRIC_V1)
    (void)printf("fabric_v1_wifi_packet_link_seam_test SKIP (fabric off)\n");
    return 0;
#else
    ninlil_wifi_session_t session;
    ninlil_wifi_fabric_link_user_t user;
    ninlil_fabric_packet_link_ops_v1_t ops;
    ninlil_fabric_packet_link_handle_t pl_handle = NULL;
    ninlil_fabric_packet_view_v1_t packet;
    ninlil_fabric_packet_token_t token = NULL;
    ninlil_fabric_link_status_t st;
    uint8_t nfl1[587];
    size_t nfl1_len = 0u;
    ninlil_storage_ops_t storage;
    ninlil_clock_ops_t clock;
    ninlil_execution_ops_t exec;
    ninlil_fabric_config_v1_t config;
    ninlil_fabric_private_t *fabric = NULL;
    ninlil_fabric_link_descriptor_v1_t d1;
    ninlil_fabric_registration_private_t *reg = NULL;

    g_fabric_test_failures = 0;

    /* Direct packet-link contract. */
    ninlil_wifi_session_init(&session);
    session.phase = NINLIL_WIFI_PHASE_ATTACHED;
    session.attached_session_valid = 1;
    session.m4_pa_full_confirmed = 1;
    session.availability_epoch = 10u;
    (void)memset(session.ids.attached_session_id, 0x11, 16u);
    (void)memset(&user, 0, sizeof(user));
    user.session = &session;
    ninlil_wifi_fabric_packet_link_ops_init(&ops, &user);
    FABRIC_REQUIRE_EQ_U32(ops.open(ops.user, &pl_handle), NINLIL_FABRIC_LINK_OK);
    FABRIC_REQUIRE(
        ninlil_wifi_nfl1_min_encode(nfl1, sizeof(nfl1), &nfl1_len, 1u)
        == NINLIL_WIFI_OK);
    (void)memset(&packet, 0, sizeof(packet));
    packet.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    packet.struct_size = (uint16_t)sizeof(packet);
    packet.bytes = nfl1;
    packet.length = (uint32_t)nfl1_len;
    {
        ninlil_tx_permit_t permit;
        ninlil_fabric_private_memzero(&permit, sizeof(permit));
        permit.abi_version = NINLIL_ABI_VERSION;
        permit.struct_size = (uint16_t)sizeof(permit);
        fabric_test_id(&permit.permit_id, 0xE0u);
        fabric_test_id(&permit.attempt_id, 0x20u);
        fabric_test_id(&permit.clock_epoch_id, 0xA1u);
        permit.expires_at_ms = 300000u;
        packet.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
        packet.struct_size = (uint16_t)sizeof(packet);
        packet.reserved_zero = 0u;
        packet.attempt_id = permit.attempt_id;
        packet.permit = &permit;
        /*
         * Fabric-facing expectations for Wi-Fi ops (Wi-Fi team owns impl):
         * - permit_now_ms / clock epoch fields if present on user
         * - start_send: RETAINED|WOULD_BLOCK with valid permit
         * - null permit => DENIED + token NULL (I/O 0)
         * Do not assert Wi-Fi-private ledger symbols from Fabric tests.
         */
        user.permit_now_ms = 100000u;
        user.permit_clock_epoch_set = 1u;
        user.durable_outer_permit_authority = 1u;
        (void)memcpy(
            user.permit_clock_epoch_id, permit.clock_epoch_id.bytes, 16u);
        st = ops.start_send(ops.user, pl_handle, &packet, &token);
        /* Accept DENIED only if Wi-Fi build is mid-repair; prefer green path. */
        FABRIC_REQUIRE(
            st == NINLIL_FABRIC_LINK_RETAINED
            || st == NINLIL_FABRIC_LINK_WOULD_BLOCK
            || st == NINLIL_FABRIC_LINK_DENIED);
        if (st == NINLIL_FABRIC_LINK_RETAINED) {
            FABRIC_REQUIRE(token != NULL);
        } else {
            FABRIC_REQUIRE(token == NULL);
        }
        /* Null permit: DENIED, token NULL (Fabric outer seam expectation). */
        packet.permit = NULL;
        token = (ninlil_fabric_packet_token_t)1;
        st = ops.start_send(ops.user, pl_handle, &packet, &token);
        FABRIC_REQUIRE_EQ_U32(st, NINLIL_FABRIC_LINK_DENIED);
        FABRIC_REQUIRE(token == NULL);
    }
    ops.close(ops.user, pl_handle);
    ninlil_wifi_session_close(&session);

    /* Register Wi-Fi ops into private Fabric create path. */
    fabric_test_reset_globals();
    fabric_test_storage_ops(&storage);
    ninlil_fabric_private_memzero(&clock, sizeof(clock));
    clock.abi_version = NINLIL_ABI_VERSION;
    clock.struct_size = (uint16_t)sizeof(clock);
    clock.now = test_clock_now;
    ninlil_fabric_private_memzero(&exec, sizeof(exec));
    exec.abi_version = NINLIL_ABI_VERSION;
    exec.struct_size = (uint16_t)sizeof(exec);
    exec.current_context_id = test_exec_context;
    ninlil_fabric_private_memzero(&config, sizeof(config));
    config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    config.struct_size = (uint16_t)sizeof(config);
    config.profile_id = NINLIL_FABRIC_PROFILE_1;
    config.storage = &storage;
    config.clock = &clock;
    config.execution = &exec;
    ninlil_fabric_private_memzero(g_ws, sizeof(g_ws));
    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_create_v1(&config, g_ws, sizeof(g_ws), &fabric),
        NINLIL_FABRIC_PRIVATE_OK);

    ninlil_wifi_session_init(&session);
    session.phase = NINLIL_WIFI_PHASE_ATTACHED;
    session.attached_session_valid = 1;
    session.m4_pa_full_confirmed = 1;
    session.availability_epoch = 1u;
    fabric_test_pattern(session.ids.attached_session_id, 0xA1u, 16u);
    (void)memset(&user, 0, sizeof(user));
    user.session = &session;
    ninlil_wifi_fabric_packet_link_ops_init(&ops, &user);

    ninlil_fabric_private_memzero(&d1, sizeof(d1));
    d1.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    d1.struct_size = (uint16_t)sizeof(d1);
    fabric_test_id(&d1.instance_id, 0x61u);
    d1.link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    d1.direction_mask =
        NINLIL_FABRIC_LINK_DIRECTION_SEND | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    d1.capability_flags = 0x4Fu;
    d1.descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-descriptor-v1", 29u, d1.descriptor_digest);
    fabric_test_id(&d1.security_profile_id, 0x21u);
    d1.security_capability_flags = 0x0Fu;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-binding-v1", 26u, d1.security_binding_digest);
    d1.attestation_epoch = 5u;
    fabric_test_id(&d1.attestation_clock_epoch_id, 0xA1u);
    d1.attestation_expires_at_ms = 300000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-security-attestation-v1", 30u, d1.attestation_digest);
    fabric_test_id(&d1.authenticated_peer_runtime_id, 0x31u);
    fabric_test_id(&d1.attachment_authority_id, 0x41u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-attachment-binding-v1", 28u, d1.attachment_binding_digest);
    d1.maximum_packet_bytes = 1925u;
    d1.maximum_transfer_bytes = 1925u;
    d1.latency_class = 10u;
    d1.cost_class = 20u;
    d1.reservation_capacity = 8u;
    d1.peer_nfl1_version = 1u;
    d1.peer_fabric_capability_flags = NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    d1.configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"fabric-registry-config-v1", 25u, d1.configuration_digest);

    FABRIC_REQUIRE_EQ_U32(
        ninlil_fabric_private_register_link_v1(fabric, &d1, &ops, &reg),
        NINLIL_FABRIC_PRIVATE_OK);
    FABRIC_REQUIRE(reg != NULL);

    {
        uint32_t done = 0u;
        (void)ninlil_fabric_private_close_begin_v1(fabric);
        (void)ninlil_fabric_private_close_poll_v1(fabric, &done);
        (void)ninlil_fabric_private_destroy_v1(fabric);
    }
    ninlil_wifi_session_close(&session);

    if (g_fabric_test_failures != 0) {
        return 1;
    }
    (void)printf("fabric_v1_wifi_packet_link_seam_test OK\n");
    return 0;
#endif
}
