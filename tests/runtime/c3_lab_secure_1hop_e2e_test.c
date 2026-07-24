/*
 * V1-LAB unit 8: C3 secure lane 1-hop E2E (both sides restart).
 */

#include "c3_lab_secure_wire.h"
#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
#include "m4_lab_primitive.h"
#include "r7_crypto_openssl3.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct secure_peer {
    ninlil_c3_lab_context_store_t store;
    ninlil_m4_lab_handshake_context_t hs;
    uint64_t last_tx_hop_counter;
    uint64_t last_tx_e2e_counter;
    uint32_t recv_ok;
    uint32_t dup_reject;
} secure_peer_t;

static ninlil_r7_crypto_provider g_provider;
static ninlil_m4_lab_membership_registry_t g_reg;
static ninlil_m4_lab_handshake_config_t g_config;

static int handshake_pair(
    secure_peer_t *controller,
    secure_peer_t *endpoint,
    ninlil_m4_lab_credential_t *endpoint_cred)
{
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_m4_lab_join_response_t response;
    ninlil_m4_lab_install_binding_t binding;
    ninlil_c3_lab_install_result_t install_result;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint->hs, endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &controller->hs, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint->hs,
                step.out_frame,
                step.out_frame_len,
                endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_decode_join_response(
                step.out_frame, step.out_frame_len, &response)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &controller->hs,
                step.out_frame,
                step.out_frame_len,
                endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);

    REQUIRE(ninlil_c3_lab_install_from_token(
                &controller->store,
                &controller->hs.install_token,
                &install_result)
        == NINLIL_C3_LAB_OK);

    (void)memset(&binding, 0, sizeof(binding));
    binding.site_domain_len = controller->hs.last_request.site_domain_len;
    (void)memcpy(
        binding.site_domain, controller->hs.last_request.site_domain, 16u);
    binding.attachment_id_len = controller->hs.last_request.device_stable_id_len;
    (void)memcpy(
        binding.attachment_id,
        controller->hs.last_request.device_stable_id,
        32u);
    binding.initiator_stable_id_len = binding.attachment_id_len;
    (void)memcpy(binding.initiator_stable_id, binding.attachment_id, 32u);
    binding.responder_stable_id_len = g_config.controller_stable_id_len;
    (void)memcpy(
        binding.responder_stable_id, g_config.controller_stable_id, 32u);
    binding.membership_epoch = controller->hs.last_request.membership_epoch;
    binding.attachment_epoch = install_result.hop_context_id;
    binding.hop_context_id = install_result.hop_context_id;
    binding.session_id = controller->hs.active_session_id;
    binding.alloc_side = 2u;

    REQUIRE(ninlil_c3_lab_install_responder(
                &endpoint->store,
                &binding,
                response.proof_hmac,
                controller->hs.challenge_nonce,
                &install_result)
        == NINLIL_C3_LAB_OK);
    return 0;
}

static int peer_init(
    secure_peer_t *peer,
    ninlil_m4_lab_handshake_role_t role,
    const ninlil_m4_lab_credential_t *cred)
{
    (void)memset(peer, 0, sizeof(*peer));
    ninlil_c3_lab_context_store_init(&peer->store, &g_provider);
    ninlil_m4_lab_handshake_init(
        &peer->hs, role, &g_reg, &g_provider, &g_config);
    peer->hs.now_ms = 7000u;
    (void)cred;
    return 0;
}

static int exchange(
    secure_peer_t *sender,
    secure_peer_t *receiver,
    const uint8_t *payload,
    size_t payload_len,
    int allow_dup_test)
{
    ninlil_c3_lab_wire_send_result_t send;
    ninlil_c3_lab_wire_recv_result_t recv;

    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &sender->store, payload, payload_len, 1u, &send)
        == NINLIL_C3_LAB_OK);
    REQUIRE(send.hop_counter > sender->last_tx_hop_counter);
    REQUIRE(send.e2e_counter > sender->last_tx_e2e_counter);
    sender->last_tx_hop_counter = send.hop_counter;
    sender->last_tx_e2e_counter = send.e2e_counter;

    REQUIRE(ninlil_c3_lab_wire_open_data(
                &receiver->store, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_OK);
    REQUIRE(recv.payload_len == payload_len);
    REQUIRE(memcmp(recv.payload, payload, payload_len) == 0);
    receiver->recv_ok += 1u;

    if (allow_dup_test != 0) {
        if (ninlil_c3_lab_wire_open_data(
                &receiver->store, send.frame, send.frame_len, &recv)
            == NINLIL_C3_LAB_REPLAY) {
            receiver->dup_reject += 1u;
        }
    }
    return 0;
}

static int run_e2e(void)
{
    secure_peer_t controller;
    secure_peer_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    const uint8_t payload[] = "c3-secure-1hop-payload";

    m4_lab_fixture_seed_membership(&g_reg);
    m4_lab_fixture_site_config(&g_config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);

    REQUIRE(peer_init(&controller, NINLIL_M4_LAB_ROLE_CONTROLLER, NULL) == 0);
    REQUIRE(peer_init(&endpoint, NINLIL_M4_LAB_ROLE_ENDPOINT, NULL) == 0);
    REQUIRE(handshake_pair(&controller, &endpoint, &endpoint_cred) == 0);

    REQUIRE(exchange(
                &controller,
                &endpoint,
                payload,
                sizeof(payload) - 1u,
                1)
        == 0);
    REQUIRE(endpoint.recv_ok == 1u);
    REQUIRE(endpoint.dup_reject == 1u);

    REQUIRE(exchange(
                &endpoint,
                &controller,
                (const uint8_t *)"ack-path",
                8u,
                0)
        == 0);
    REQUIRE(controller.recv_ok == 1u);

    REQUIRE(ninlil_c3_lab_context_clean_restart(&controller.store)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_context_clean_restart(&endpoint.store)
        == NINLIL_C3_LAB_OK);
    REQUIRE(controller.store.nonce_reuse_count == 0u);

    g_config.next_session_id += 1u;
    g_config.next_hop_context_id += 1u;
    controller.last_tx_hop_counter = 0u;
    controller.last_tx_e2e_counter = 0u;
    endpoint.last_tx_hop_counter = 0u;
    endpoint.last_tx_e2e_counter = 0u;
    endpoint.recv_ok = 0u;
    endpoint.dup_reject = 0u;
    controller.recv_ok = 0u;

    REQUIRE(peer_init(&controller, NINLIL_M4_LAB_ROLE_CONTROLLER, NULL) == 0);
    REQUIRE(peer_init(&endpoint, NINLIL_M4_LAB_ROLE_ENDPOINT, NULL) == 0);
    REQUIRE(handshake_pair(&controller, &endpoint, &endpoint_cred) == 0);

    REQUIRE(exchange(
                &controller,
                &endpoint,
                payload,
                sizeof(payload) - 1u,
                0)
        == 0);
    REQUIRE(endpoint.recv_ok == 1u);
    REQUIRE(endpoint.dup_reject == 0u);
    REQUIRE(controller.last_tx_hop_counter == 1u);
    REQUIRE(controller.store.nonce_reuse_count == 0u);

    REQUIRE(ninlil_c3_lab_context_commit_unknown_restart(&controller.store)
        == NINLIL_C3_LAB_OK);
    REQUIRE(controller.store.state
        == NINLIL_C3_LAB_STATE_COMMIT_UNKNOWN);
    return 0;
}

int main(void)
{
    if (ninlil_r7_crypto_openssl3_provider_init(&g_provider)
        != NINLIL_R7_CRYPTO_OK) {
        return 1;
    }
    if (run_e2e() != 0) {
        (void)fprintf(stderr, "c3_lab_secure_1hop_e2e_test failed\n");
        return 1;
    }
    (void)printf("c3_lab_secure_1hop_e2e_test ok\n");
    return 0;
}
