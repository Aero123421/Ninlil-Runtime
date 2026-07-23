/*
 * V1-LAB unit 7: M4 Join/Attachment handshake + membership + install token mint.
 */

#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
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

static int init_provider(void)
{
    if (ninlil_r7_crypto_openssl3_provider_init(&g_provider)
        != NINLIL_R7_CRYPTO_OK) {
        return 1;
    }
    return 0;
}

static int run_handshake_success(void)
{
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t controller;
    ninlil_m4_lab_handshake_context_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_credential_t controller_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_r7_t1c_hop_install_ops_t token_ops;
    ninlil_r7_t1c_hop_install_claim_t claim;
    ninlil_status_t gate_status;

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);
    m4_lab_fixture_controller_credential(&controller_cred);

    ninlil_m4_lab_handshake_init(
        &controller,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &reg,
        &g_provider,
        &config);
    controller.now_ms = 1000u;

    ninlil_m4_lab_handshake_init(
        &endpoint,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &reg,
        &g_provider,
        &config);
    endpoint.now_ms = 1000u;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(step.out_frame_len > 0u);

    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &controller, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(step.out_frame_type == NINLIL_M4_LAB_FRAME_JOIN_CHALLENGE);

    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(step.out_frame_type == NINLIL_M4_LAB_FRAME_JOIN_RESPONSE);

    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &controller,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(step.out_frame_type == NINLIL_M4_LAB_FRAME_JOIN_INSTALL);
    REQUIRE(controller.has_install_token != 0);
    REQUIRE(controller.mint_result.success != 0);

    gate_status = ninlil_v1_durable_writer_gate_check(
        NINLIL_V1_DURABLE_OP_M4_INSTALL_TOKEN_COMMIT,
        (ninlil_bytes_view_t){
            controller.mint_result.durable_key, 16u},
        (ninlil_bytes_view_t){
            controller.mint_result.durable_value,
            NINLIL_M4_LAB_DURABLE_RECORD_BYTES});
    REQUIRE(gate_status == NINLIL_OK);

    ninlil_m4_lab_install_token_ops_init(&token_ops);
    (void)memset(&claim, 0, sizeof(claim));
    REQUIRE(ninlil_m4_lab_install_token_consume(
                NULL,
                &controller.install_token,
                &claim)
        == NINLIL_R7_T1C_HOP_ACCEPT_OK);
    REQUIRE(claim.struct_size == NINLIL_R7_T1C_HOP_CLAIM_BYTES);
    REQUIRE(claim.environment_code == NINLIL_R7_BINDING_ENV_LAB);
    REQUIRE(claim.membership_epoch == 42u);

    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_install(
                &endpoint, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(endpoint.state == NINLIL_M4_LAB_ATTACHMENT_ATTACHED);
    return 0;
}

static int run_reject_wrong_credential(void)
{
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t controller;
    ninlil_m4_lab_handshake_context_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_credential_t wrong_cred;
    ninlil_m4_lab_handshake_step_result_t step;

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);
    m4_lab_fixture_wrong_credential(&wrong_cred);

    ninlil_m4_lab_handshake_init(
        &controller,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &reg,
        &g_provider,
        &config);
    controller.now_ms = 2000u;
    ninlil_m4_lab_handshake_init(
        &endpoint,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &reg,
        &g_provider,
        &config);
    endpoint.now_ms = 2000u;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &controller, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint,
                step.out_frame,
                step.out_frame_len,
                &wrong_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &controller,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success == 0);
    REQUIRE(step.reject_reason == NINLIL_M4_LAB_REJECT_CREDENTIAL);
    REQUIRE(controller.has_install_token == 0);
    return 0;
}

static int run_reject_bad_challenge_crc(void)
{
    ninlil_m4_lab_join_challenge_t ch;
    uint8_t frame[128];
    int32_t enc;
    ninlil_m4_lab_join_response_t resp;
    ninlil_m4_lab_status_t st;

    (void)memset(&ch, 0, sizeof(ch));
    ch.nonce[0] = 1u;
    ch.expires_ms = 5000u;
    ch.membership_epoch = 42u;
    ch.session_id = 77u;
    enc = ninlil_m4_lab_encode_join_challenge(&ch, frame, sizeof(frame));
    REQUIRE(enc > 0);
    frame[(size_t)enc - 1u] ^= 0xffu;
    st = ninlil_m4_lab_decode_join_challenge(
        frame, (size_t)enc, &ch);
    REQUIRE(st == NINLIL_M4_LAB_CRC);
    st = ninlil_m4_lab_decode_join_response(
        frame, (size_t)enc, &resp);
    REQUIRE(st == NINLIL_M4_LAB_STRUCTURAL || st == NINLIL_M4_LAB_CRC);
    return 0;
}

static int run_reject_expired_challenge(void)
{
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t controller;
    ninlil_m4_lab_handshake_context_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_handshake_step_result_t step;

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);

    ninlil_m4_lab_handshake_init(
        &controller,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &reg,
        &g_provider,
        &config);
    controller.now_ms = 1000u;
    ninlil_m4_lab_handshake_init(
        &endpoint,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &reg,
        &g_provider,
        &config);
    endpoint.now_ms = 1000u + NINLIL_M4_LAB_CHALLENGE_TTL_MS + 1u;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &controller, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint,
                step.out_frame,
                step.out_frame_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success == 0);
    REQUIRE(step.reject_reason == NINLIL_M4_LAB_REJECT_EXPIRED);
    return 0;
}

static int run_reject_replay(void)
{
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t controller;
    ninlil_m4_lab_handshake_context_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    uint8_t challenge_frame[128];
    size_t challenge_len;

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);

    ninlil_m4_lab_handshake_init(
        &controller,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &reg,
        &g_provider,
        &config);
    controller.now_ms = 3000u;
    ninlil_m4_lab_handshake_init(
        &endpoint,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &reg,
        &g_provider,
        &config);
    endpoint.now_ms = 3000u;

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &controller, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    challenge_len = step.out_frame_len;
    (void)memcpy(challenge_frame, step.out_frame, challenge_len);

    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint,
                challenge_frame,
                challenge_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);

    endpoint.state = NINLIL_M4_LAB_ATTACHMENT_DISCOVERING;
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &endpoint,
                challenge_frame,
                challenge_len,
                &endpoint_cred,
                &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success == 0);
    REQUIRE(step.reject_reason == NINLIL_M4_LAB_REJECT_REPLAY);
    return 0;
}

static int run_reject_non_member(void)
{
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_m4_lab_handshake_context_t controller;
    ninlil_m4_lab_handshake_context_t endpoint;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_m4_lab_bytes_t unknown;
    static const char k_unknown[] = "not-enrolled-device";

    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    m4_lab_fixture_endpoint_credential(&endpoint_cred);

    unknown.bytes = (const uint8_t *)k_unknown;
    unknown.length = (uint16_t)(sizeof(k_unknown) - 1u);
    (void)ninlil_m4_lab_membership_register(
        &reg,
        unknown,
        NINLIL_M4_LAB_MEMBERSHIP_PENDING,
        42u);

    ninlil_m4_lab_handshake_init(
        &controller,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &reg,
        &g_provider,
        &config);
    controller.now_ms = 4000u;
    ninlil_m4_lab_handshake_init(
        &endpoint,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &reg,
        &g_provider,
        &config);
    endpoint.now_ms = 4000u;

    endpoint_cred.stable_id_len = unknown.length;
    (void)memcpy(
        endpoint_cred.stable_id, unknown.bytes, (size_t)unknown.length);

    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(
                &endpoint, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success == 0);
    REQUIRE(step.reject_reason == NINLIL_M4_LAB_REJECT_MEMBERSHIP);
    return 0;
}

static int run_one(const char *name, int (*fn)(void))
{
    int rc = fn();
    if (rc != 0) {
        (void)fprintf(stderr, "FAILED %s\n", name);
    } else {
        (void)fprintf(stderr, "PASS %s\n", name);
    }
    return rc;
}

int main(void)
{
    int failures = 0;

    if (init_provider() != 0) {
        (void)fprintf(stderr, "provider init failed\n");
        return 1;
    }

    failures += run_one("handshake_success", run_handshake_success);
    failures += run_one("reject_wrong_credential", run_reject_wrong_credential);
    failures += run_one("reject_bad_challenge_crc", run_reject_bad_challenge_crc);
    failures += run_one("reject_expired_challenge", run_reject_expired_challenge);
    failures += run_one("reject_replay", run_reject_replay);
    failures += run_one("reject_non_member", run_reject_non_member);

    if (failures != 0) {
        return 1;
    }
    (void)fprintf(stderr, "m4_lab_join_handshake_test: all passed\n");
    return 0;
}
