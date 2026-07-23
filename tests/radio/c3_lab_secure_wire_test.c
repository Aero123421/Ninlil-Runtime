/*
 * V1-LAB unit 8: C3 secure wire + context lifecycle.
 */

#include "c3_lab_secure_wire.h"
#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
#include "m4_lab_primitive.h"
#include "r7_crypto_openssl3.h"
#include "v1_durable_allowlist.h"

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

static ninlil_r7_crypto_provider g_provider;
static ninlil_m4_lab_membership_registry_t g_reg;
static ninlil_m4_lab_handshake_config_t g_config;

static int init_provider(void)
{
    if (ninlil_r7_crypto_openssl3_provider_init(&g_provider)
        != NINLIL_R7_CRYPTO_OK) {
        return 1;
    }
    m4_lab_fixture_seed_membership(&g_reg);
    m4_lab_fixture_site_config(&g_config);
    return 0;
}

static int run_full_handshake_install(
    ninlil_c3_lab_context_store_t *controller,
    ninlil_c3_lab_context_store_t *endpoint,
    ninlil_m4_lab_install_binding_t *out_binding,
    uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN])
{
    ninlil_m4_lab_handshake_context_t ctrl_hs;
    ninlil_m4_lab_handshake_context_t end_hs;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_credential_t controller_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_m4_lab_join_response_t response;
    ninlil_c3_lab_install_result_t install_result;

    m4_lab_fixture_endpoint_credential(&endpoint_cred);
    m4_lab_fixture_controller_credential(&controller_cred);

    ninlil_m4_lab_handshake_init(
        &ctrl_hs, NINLIL_M4_LAB_ROLE_CONTROLLER, &g_reg, &g_provider, &g_config);
    ctrl_hs.now_ms = 1000u;
    ninlil_m4_lab_handshake_init(
        &end_hs, NINLIL_M4_LAB_ROLE_ENDPOINT, &g_reg, &g_provider, &g_config);
    end_hs.now_ms = 1000u;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &end_hs, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &ctrl_hs, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &end_hs,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_decode_join_response(
                step.out_frame, step.out_frame_len, &response)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &ctrl_hs,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ctrl_hs.has_install_token != 0);

    REQUIRE(ninlil_c3_lab_install_from_token(
                controller, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_OK);

    (void)memcpy(out_binding->site_domain, ctrl_hs.last_request.site_domain, 16u);
    out_binding->site_domain_len = ctrl_hs.last_request.site_domain_len;
    out_binding->attachment_id_len = ctrl_hs.last_request.device_stable_id_len;
    (void)memcpy(
        out_binding->attachment_id,
        ctrl_hs.last_request.device_stable_id,
        32u);
    out_binding->initiator_stable_id_len = out_binding->attachment_id_len;
    (void)memcpy(
        out_binding->initiator_stable_id,
        out_binding->attachment_id,
        32u);
    out_binding->responder_stable_id_len = g_config.controller_stable_id_len;
    (void)memcpy(
        out_binding->responder_stable_id,
        g_config.controller_stable_id,
        32u);
    out_binding->membership_epoch = ctrl_hs.last_request.membership_epoch;
    out_binding->attachment_epoch = install_result.hop_context_id;
    out_binding->hop_context_id = install_result.hop_context_id;
    out_binding->session_id = ctrl_hs.active_session_id;
    out_binding->direction_code = NINLIL_R7_BINDING_DIR_IR;
    out_binding->alloc_side = 2u;
    (void)memcpy(proof_hmac, response.proof_hmac, NINLIL_M4_LAB_PROOF_LEN);
    (void)memcpy(challenge_nonce, ctrl_hs.challenge_nonce, NINLIL_M4_LAB_NONCE_LEN);

    REQUIRE(ninlil_c3_lab_install_responder(
                endpoint,
                out_binding,
                response.proof_hmac,
                ctrl_hs.challenge_nonce,
                &install_result)
        == NINLIL_C3_LAB_OK);
    return 0;
}

static int run_happy_path(void)
{
    ninlil_c3_lab_context_store_t controller;
    ninlil_c3_lab_context_store_t endpoint;
    ninlil_m4_lab_install_binding_t binding;
    uint8_t proof[32];
    uint8_t nonce[NINLIL_M4_LAB_NONCE_LEN];
    ninlil_c3_lab_wire_send_result_t send;
    ninlil_c3_lab_wire_recv_result_t recv;
    const uint8_t payload[] = "lab-secure-payload";
    uint8_t durable_key[16];
    uint8_t durable_value[48];
    ninlil_status_t gate_status;

    ninlil_c3_lab_context_store_init(&controller, &g_provider);
    ninlil_c3_lab_context_store_init(&endpoint, &g_provider);
    REQUIRE(run_full_handshake_install(
                &controller, &endpoint, &binding, proof, nonce)
        == 0);

    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &controller,
                payload,
                sizeof(payload) - 1u,
                1u,
                &send)
        == NINLIL_C3_LAB_OK);
    REQUIRE(send.frame_len > 0u);
    REQUIRE(send.hop_counter == 1u);
    REQUIRE(send.e2e_counter == 1u);

    REQUIRE(ninlil_c3_lab_wire_open_data(
                &endpoint, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_OK);
    REQUIRE(recv.payload_len == sizeof(payload) - 1u);
    REQUIRE(memcmp(recv.payload, payload, recv.payload_len) == 0);

    REQUIRE(ninlil_c3_lab_encode_durable_admission(
                &endpoint,
                recv.hop_context_id,
                NINLIL_C3_LAB_LANE_DATA,
                0u,
                recv.hop_counter,
                durable_key,
                durable_value)
        == NINLIL_C3_LAB_OK);
    gate_status = ninlil_v1_durable_writer_gate_check(
        NINLIL_V1_DURABLE_OP_C3_REPLAY_ADMISSION_COMMIT,
        (ninlil_bytes_view_t){durable_key, 16u},
        (ninlil_bytes_view_t){durable_value, 48u});
    REQUIRE(gate_status == NINLIL_OK);

    REQUIRE(ninlil_c3_lab_wire_seal_ack(
                &endpoint, (const uint8_t *)"ok", 2u, &send)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_wire_open_ack(
                &controller, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_OK);
    REQUIRE(recv.payload_len == 2u);
    return 0;
}

static int run_reject_replay(void)
{
    ninlil_c3_lab_context_store_t controller;
    ninlil_c3_lab_context_store_t endpoint;
    ninlil_m4_lab_install_binding_t binding;
    uint8_t proof[32];
    uint8_t nonce[NINLIL_M4_LAB_NONCE_LEN];
    ninlil_c3_lab_wire_send_result_t send;
    ninlil_c3_lab_wire_recv_result_t recv;
    const uint8_t payload[] = "replay-test";

    ninlil_c3_lab_context_store_init(&controller, &g_provider);
    ninlil_c3_lab_context_store_init(&endpoint, &g_provider);
    REQUIRE(run_full_handshake_install(
                &controller, &endpoint, &binding, proof, nonce)
        == 0);

    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &controller, payload, sizeof(payload) - 1u, 0u, &send)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_wire_open_data(
                &endpoint, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_wire_open_data(
                &endpoint, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_REPLAY);
    return 0;
}

static int run_reject_tamper(void)
{
    ninlil_c3_lab_context_store_t controller;
    ninlil_c3_lab_context_store_t endpoint;
    ninlil_m4_lab_install_binding_t binding;
    uint8_t proof[32];
    uint8_t nonce[NINLIL_M4_LAB_NONCE_LEN];
    ninlil_c3_lab_wire_send_result_t send;
    ninlil_c3_lab_wire_recv_result_t recv;
    const uint8_t payload[] = "tamper-test";

    ninlil_c3_lab_context_store_init(&controller, &g_provider);
    ninlil_c3_lab_context_store_init(&endpoint, &g_provider);
    REQUIRE(run_full_handshake_install(
                &controller, &endpoint, &binding, proof, nonce)
        == 0);

    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &controller, payload, sizeof(payload) - 1u, 0u, &send)
        == NINLIL_C3_LAB_OK);
    send.frame[send.frame_len - 1u] ^= 0x01u;
    REQUIRE(ninlil_c3_lab_wire_open_data(
                &endpoint, send.frame, send.frame_len, &recv)
        == NINLIL_C3_LAB_AUTH_FAILED);
    return 0;
}

static int run_reject_stale_token(void)
{
    ninlil_c3_lab_context_store_t controller;
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t ctrl_hs;
    ninlil_m4_lab_handshake_context_t end_hs;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_credential_t controller_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_c3_lab_install_result_t install_result;

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);
    m4_lab_fixture_controller_credential(&controller_cred);

    ninlil_c3_lab_context_store_init(&controller, &g_provider);
    ninlil_m4_lab_handshake_init(
        &ctrl_hs, NINLIL_M4_LAB_ROLE_CONTROLLER, &reg, &g_provider, &config);
    ninlil_m4_lab_handshake_init(
        &end_hs, NINLIL_M4_LAB_ROLE_ENDPOINT, &reg, &g_provider, &config);

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &end_hs, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &ctrl_hs, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &end_hs,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &ctrl_hs,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);

    REQUIRE(ninlil_c3_lab_install_from_token(
                &controller, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_install_from_token(
                &controller, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_STALE);
    return 0;
}

static int run_restart_fresh_handshake(void)
{
    ninlil_c3_lab_context_store_t controller;
    ninlil_c3_lab_context_store_t endpoint;
    ninlil_m4_lab_install_binding_t binding;
    uint8_t proof[32];
    uint8_t nonce[NINLIL_M4_LAB_NONCE_LEN];
    ninlil_c3_lab_wire_send_result_t send;
    const uint8_t payload[] = "restart";

    ninlil_c3_lab_context_store_init(&controller, &g_provider);
    ninlil_c3_lab_context_store_init(&endpoint, &g_provider);
    REQUIRE(run_full_handshake_install(
                &controller, &endpoint, &binding, proof, nonce)
        == 0);

    REQUIRE(ninlil_c3_lab_context_clean_restart(&controller)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_context_clean_restart(&endpoint)
        == NINLIL_C3_LAB_OK);
    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &controller, payload, sizeof(payload) - 1u, 0u, &send)
        == NINLIL_C3_LAB_FENCED);

    g_config.next_session_id += 1u;
    g_config.next_hop_context_id += 1u;
    REQUIRE(run_full_handshake_install(
                &controller, &endpoint, &binding, proof, nonce)
        == 0);
    REQUIRE(ninlil_c3_lab_wire_seal_data(
                &controller, payload, sizeof(payload) - 1u, 0u, &send)
        == NINLIL_C3_LAB_OK);
    return 0;
}

static int run_commit_unknown_restart(void)
{
    ninlil_c3_lab_context_store_t store;

    ninlil_c3_lab_context_store_init(&store, &g_provider);
    REQUIRE(ninlil_c3_lab_context_commit_unknown_restart(&store)
        == NINLIL_C3_LAB_OK);
    REQUIRE(store.state == NINLIL_C3_LAB_STATE_COMMIT_UNKNOWN);
    return 0;
}

int main(void)
{
    if (init_provider() != 0) {
        return 1;
    }

    if (run_happy_path() != 0) {
        (void)fprintf(stderr, "FAIL happy_path\n");
        return 1;
    }
    (void)printf("PASS happy_path\n");

    if (run_reject_replay() != 0) {
        (void)fprintf(stderr, "FAIL reject_replay\n");
        return 1;
    }
    (void)printf("PASS reject_replay\n");

    if (run_reject_tamper() != 0) {
        (void)fprintf(stderr, "FAIL reject_tamper\n");
        return 1;
    }
    (void)printf("PASS reject_tamper\n");

    if (run_reject_stale_token() != 0) {
        (void)fprintf(stderr, "FAIL reject_stale_token\n");
        return 1;
    }
    (void)printf("PASS reject_stale_token\n");

    if (run_restart_fresh_handshake() != 0) {
        (void)fprintf(stderr, "FAIL restart_fresh_handshake\n");
        return 1;
    }
    (void)printf("PASS restart_fresh_handshake\n");

    if (run_commit_unknown_restart() != 0) {
        (void)fprintf(stderr, "FAIL commit_unknown_restart\n");
        return 1;
    }
    (void)printf("PASS commit_unknown_restart\n");

    (void)printf("c3_lab_secure_wire_test: all passed\n");
    return 0;
}
