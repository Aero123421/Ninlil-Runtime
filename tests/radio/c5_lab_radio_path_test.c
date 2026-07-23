/*
 * V1-LAB item 9: C5-LAB SX1262 software path tests (R1..R9 closure).
 */

#include "c5_lab_radio_path.h"
#include "c6_lab_enforcement.h"
#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
#include "profile_loader.h"
#include "profile_r5_golden_profiles.h"
#include "r7_crypto_openssl3.h"

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(                                                     \
                stderr, "REQUIRE fail %s:%d: %s\n", __FILE__, __LINE__, #c);   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define T_CHANNEL ((uint32_t)2u)
#define T_TERM ((uint64_t)11u)
#define T_GEN ((uint64_t)3u)
#define T_EPOCH ((uint64_t)9u)
#define T_SITE_REV ((uint32_t)4u)

static void fill_id(ninlil_radio_hal_id_t *id, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void fill_digest(uint8_t *d, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        d[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void make_assign(ninlil_r5_site_assignment_t *a)
{
    (void)memset(a, 0, sizeof(*a));
    fill_id(&a->site_assignment_id, 0x30u);
    a->site_assignment_rev = T_SITE_REV;
    a->site_assignment_epoch = T_EPOCH;
    a->controller_term = T_TERM;
    fill_digest(a->assignment_digest, 0x50u);
    a->permit_bind_generation = T_GEN;
    fill_id(&a->transmitter_id, 0x40u);
    a->channel_id = T_CHANNEL;
    a->phy.bandwidth_hz = 125000u;
    a->phy.spreading_factor = 7u;
    a->phy.coding_rate_denom = 5u;
    a->phy.preamble_symbols = 8u;
    a->phy.tx_power_mdb = 10000;
    a->phy.phy_flags = 0u;
}

typedef struct radio_env {
    ninlil_r7_crypto_provider provider;
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_c3_lab_context_store_t tx_store;
    ninlil_c3_lab_context_store_t rx_store;
    ninlil_r5_object_t r5obj;
    ninlil_r5_t *r5;
    ninlil_pcp_object_t pcpobj;
    ninlil_pcp_t *pcp;
    ninlil_c6_lab_object_t c6obj;
    ninlil_c6_lab_t *c6;
    ninlil_c5_lab_radio_object_t radio_tx_obj;
    ninlil_c5_lab_radio_t *radio_tx;
    ninlil_c5_lab_radio_object_t radio_rx_obj;
    ninlil_c5_lab_radio_t *radio_rx;
    ninlil_c5_lab_radio_channel_t channel;
    ninlil_test_storage_t *storage;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    uint8_t hw_doc[NINLIL_R5_HW_DOC_BYTES];
    uint8_t reg_doc[NINLIL_R5_REG_DOC_BYTES];
} radio_env_t;

static int install_contexts(radio_env_t *e)
{
    ninlil_m4_lab_handshake_context_t ctrl_hs;
    ninlil_m4_lab_handshake_context_t end_hs;
    ninlil_m4_lab_credential_t endpoint_cred;
    ninlil_m4_lab_handshake_step_result_t step;
    ninlil_m4_lab_join_response_t response;
    ninlil_m4_lab_install_binding_t binding;
    ninlil_c3_lab_install_result_t install_result;

    m4_lab_fixture_endpoint_credential(&endpoint_cred);
    ninlil_m4_lab_handshake_init(
        &ctrl_hs,
        NINLIL_M4_LAB_ROLE_CONTROLLER,
        &e->reg,
        &e->provider,
        &e->config);
    ctrl_hs.now_ms = 1000u;
    ninlil_m4_lab_handshake_init(
        &end_hs,
        NINLIL_M4_LAB_ROLE_ENDPOINT,
        &e->reg,
        &e->provider,
        &e->config);
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
    REQUIRE(ninlil_c3_lab_install_from_token(
                &e->tx_store, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_OK);
    (void)memset(&binding, 0, sizeof(binding));
    binding.site_domain_len = ctrl_hs.last_request.site_domain_len;
    (void)memcpy(binding.site_domain, ctrl_hs.last_request.site_domain, 16u);
    binding.attachment_id_len = ctrl_hs.last_request.device_stable_id_len;
    (void)memcpy(binding.attachment_id, ctrl_hs.last_request.device_stable_id, 32u);
    binding.initiator_stable_id_len = binding.attachment_id_len;
    (void)memcpy(binding.initiator_stable_id, binding.attachment_id, 32u);
    binding.responder_stable_id_len = e->config.controller_stable_id_len;
    (void)memcpy(
        binding.responder_stable_id, e->config.controller_stable_id, 32u);
    binding.membership_epoch = ctrl_hs.last_request.membership_epoch;
    binding.attachment_epoch = install_result.hop_context_id;
    binding.hop_context_id = install_result.hop_context_id;
    binding.session_id = ctrl_hs.active_session_id;
    binding.alloc_side = 2u;
    REQUIRE(ninlil_c3_lab_install_responder(
                &e->rx_store,
                &binding,
                response.proof_hmac,
                ctrl_hs.challenge_nonce,
                &install_result)
        == NINLIL_C3_LAB_OK);
    return 0;
}

static int env_setup(radio_env_t *e)
{
    ninlil_test_storage_config_t cfg;
    ninlil_pcp_live_profile_t live;
    ninlil_pcp_instance_seed_t seed;
    ninlil_radio_hal_live_binding_t r5live;
    ninlil_r5_site_assignment_t assign;
    ninlil_r5_error_t err;
    ninlil_pcp_error_t pcp_err;

    (void)memset(e, 0, sizeof(*e));
    REQUIRE(
        ninlil_r7_crypto_openssl3_provider_init(&e->provider) == NINLIL_R7_CRYPTO_OK);
    m4_lab_fixture_seed_membership(&e->reg);
    m4_lab_fixture_site_config(&e->config);
    ninlil_c3_lab_context_store_init(&e->tx_store, &e->provider);
    ninlil_c3_lab_context_store_init(&e->rx_store, &e->provider);
    REQUIRE(install_contexts(e) == 0);
    (void)memcpy(e->hw_doc, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES);
    (void)memcpy(e->reg_doc, k_r5_golden_reg_v1, NINLIL_R5_REG_DOC_BYTES);
    make_assign(&assign);
    e->r5obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    REQUIRE(ninlil_r5_init_object(&e->r5obj, &e->r5) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_hardware_profile(
            e->r5, e->hw_doc, NINLIL_R5_HW_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_regulatory_profile(
            e->r5, e->reg_doc, NINLIL_R5_REG_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_activate_profiles(e->r5, &err) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_bind_site_assignment(e->r5, &assign, &err) == NINLIL_R5_OK);
    e->pcpobj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    REQUIRE(ninlil_pcp_init_object(&e->pcpobj, &e->pcp) == NINLIL_PCP_OK);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 64u;
    cfg.max_bytes_per_namespace = 65536u;
    e->storage = ninlil_test_storage_create(&cfg);
    e->clock = ninlil_test_clock_create();
    e->entropy = ninlil_test_entropy_create(0xC509u, 1u);
    REQUIRE(e->storage != NULL && e->clock != NULL && e->entropy != NULL);
    REQUIRE(
        ninlil_pcp_bind_storage(
            e->pcp, ninlil_test_storage_ops(e->storage), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_clock(e->pcp, ninlil_test_clock_ops(e->clock), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_entropy(
            e->pcp, ninlil_test_entropy_ops(e->entropy), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_build_live_binding(e->r5, &r5live, &err) == NINLIL_R5_OK);
    live = r5live;
    REQUIRE(ninlil_pcp_bind_live_profile(e->pcp, &live, &pcp_err) == NINLIL_PCP_OK);
    for (size_t i = 0u; i < 16u; ++i) {
        seed.bytes[i] = (uint8_t)(0x50u + (uint8_t)i);
    }
    REQUIRE(
        ninlil_pcp_publish_initial_meta(e->pcp, &seed, &pcp_err) == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_bind_pcp(e->r5, e->pcp, &err) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_c6_lab_init_object(&e->c6obj, e->r5, &e->c6, NULL) == NINLIL_C6_LAB_OK);
    ninlil_c5_lab_radio_channel_init(&e->channel);
    REQUIRE(
        ninlil_c5_lab_radio_init_object(
            &e->radio_tx_obj, &e->tx_store, e->c6, &e->channel, &e->radio_tx)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(
        ninlil_c5_lab_radio_init_object(
            &e->radio_rx_obj, &e->rx_store, e->c6, &e->channel, &e->radio_rx)
        == NINLIL_C5_LAB_RADIO_OK);
    return 0;
}

static int test_happy_tx_rx(void)
{
    radio_env_t e;
    const uint8_t payload[] = "c5-lab-radio-data";
    uint8_t recv[64];
    size_t recv_len = 0u;
    ninlil_c5_lab_radio_stats_t stats;

    REQUIRE(env_setup(&e) == 0);
    REQUIRE(strcmp(ninlil_c5_lab_mac_owner_label(), "NONE_R8_NOT_ADOPTED") == 0);
    REQUIRE(
        ninlil_c5_lab_radio_tx_data(
            e.radio_tx, payload, sizeof(payload) - 1u, &e.channel)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(
        ninlil_c5_lab_radio_irq_rx_admit(
            e.radio_rx, recv, sizeof(recv), &recv_len)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(recv_len == sizeof(payload) - 1u);
    REQUIRE(memcmp(recv, payload, recv_len) == 0);
    ninlil_c5_lab_radio_stats_snapshot(e.radio_tx, &stats);
    REQUIRE(stats.spi_tx_count >= 1u);
    REQUIRE(stats.tx_ok >= 1u);
    (void)fprintf(stderr, "PASS happy_tx_rx\n");
    return 0;
}

static int test_replay_reject(void)
{
    radio_env_t e;
    const uint8_t payload[] = "replay-me";
    uint8_t recv[64];
    size_t recv_len = 0u;

    REQUIRE(env_setup(&e) == 0);
    REQUIRE(
        ninlil_c5_lab_radio_tx_data(
            e.radio_tx, payload, sizeof(payload) - 1u, &e.channel)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(
        ninlil_c5_lab_radio_irq_rx_admit(
            e.radio_rx, recv, sizeof(recv), &recv_len)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(
        ninlil_c5_lab_radio_irq_rx_admit(
            e.radio_rx, recv, sizeof(recv), &recv_len)
        == NINLIL_C5_LAB_RADIO_FIFO_EMPTY);
    (void)fprintf(stderr, "PASS replay_reject\n");
    return 0;
}

static int test_auth_fail(void)
{
    radio_env_t e;
    const uint8_t payload[] = "tamper";
    uint8_t frame[255];
    uint32_t frame_len = 0u;
    uint8_t recv[64];
    size_t recv_len = 0u;

    REQUIRE(env_setup(&e) == 0);
    REQUIRE(
        ninlil_c5_lab_radio_tx_data(
            e.radio_tx, payload, sizeof(payload) - 1u, &e.channel)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(e.channel.count >= 1u);
    frame_len = e.channel.frame_lens[e.channel.head];
    (void)memcpy(frame, e.channel.frames[e.channel.head], frame_len);
    frame[frame_len - 1u] ^= 0xFFu;
    e.channel.head = 0u;
    e.channel.tail = 0u;
    e.channel.count = 0u;
    REQUIRE(ninlil_c5_lab_radio_channel_deliver(&e.channel, frame, frame_len) != 0);
    REQUIRE(
        ninlil_c5_lab_radio_irq_rx_admit(
            e.radio_rx, recv, sizeof(recv), &recv_len)
        == NINLIL_C5_LAB_RADIO_AUTH_FAILED);
    (void)fprintf(stderr, "PASS auth_fail\n");
    return 0;
}

static int test_permit_fail(void)
{
    radio_env_t e;
    const uint8_t payload[] = "deny";
    ninlil_c6_lab_stats_t c6_stats;

    REQUIRE(env_setup(&e) == 0);
    REQUIRE(ninlil_c6_lab_shutdown(e.c6, NULL) == NINLIL_C6_LAB_OK);
    REQUIRE(
        ninlil_c5_lab_radio_tx_data(
            e.radio_tx, payload, sizeof(payload) - 1u, &e.channel)
        == NINLIL_C5_LAB_RADIO_PERMIT_DENIED);
    ninlil_c6_lab_stats(e.c6, &c6_stats);
    REQUIRE(c6_stats.spi_tx_count == 0u);
    (void)fprintf(stderr, "PASS permit_fail\n");
    return 0;
}

int main(void)
{
    REQUIRE(test_happy_tx_rx() == 0);
    REQUIRE(test_replay_reject() == 0);
    REQUIRE(test_auth_fail() == 0);
    REQUIRE(test_permit_fail() == 0);
    (void)fprintf(stderr, "c5_lab_radio_path_test: all passed\n");
    return 0;
}
