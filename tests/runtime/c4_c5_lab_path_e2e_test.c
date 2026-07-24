/*
 * V1-LAB item 9: C4/C5-LAB integrated path E2E (submit -> secure wire -> USB/radio).
 */

#include "c4_c5_lab_wire.h"
#include "c4_lab_usb_path.h"
#include "c5_lab_radio_path.h"
#include "c6_lab_enforcement.h"
#include "fake_byte_stream.h"
#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
#include "profile_loader.h"
#include "profile_r5_golden_profiles.h"
#include "r7_crypto_openssl3.h"
#include "runtime_v1_capability.h"

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

typedef struct cookie_rng_ctx {
    uint64_t seq;
} cookie_rng_ctx_t;

static int cookie_rng_cb(void *ctx, uint64_t *out)
{
    cookie_rng_ctx_t *c = (cookie_rng_ctx_t *)ctx;
    if (c == NULL || out == NULL) {
        return -1;
    }
    c->seq += 0x2222222222222222ull;
    *out = c->seq;
    return 0;
}

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

static void pump_pair(
    ninlil_fake_byte_stream_t *a,
    ninlil_fake_byte_stream_t *b)
{
    uint8_t buf[2048];
    uint32_t n;

    n = ninlil_fake_byte_stream_take_tx(a, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(b, buf, n);
    }
    n = ninlil_fake_byte_stream_take_tx(b, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(a, buf, n);
    }
}

static int bring_up_usb(
    ninlil_c4_lab_usb_t *ctrl,
    ninlil_c4_lab_usb_t *cell,
    ninlil_fake_byte_stream_t *ctrl_fake,
    ninlil_fake_byte_stream_t *cell_fake)
{
    uint64_t now_ms = 5000u;
    uint32_t i;

    for (i = 0u; i < 200u; ++i) {
        REQUIRE(ninlil_c4_lab_usb_step(ctrl, now_ms, 50u) == NINLIL_C4_LAB_USB_OK);
        REQUIRE(ninlil_c4_lab_usb_step(cell, now_ms, 50u) == NINLIL_C4_LAB_USB_OK);
        pump_pair(ctrl_fake, cell_fake);
        if (ninlil_c4_lab_usb_session_active(ctrl) != 0
            && ninlil_c4_lab_usb_session_active(cell) != 0) {
            return 0;
        }
        now_ms += 10u;
    }
    return 1;
}

static int install_radio_contexts(
    ninlil_r7_crypto_provider *provider,
    ninlil_m4_lab_membership_registry_t *reg,
    ninlil_m4_lab_handshake_config_t *config,
    ninlil_c3_lab_context_store_t *tx_store,
    ninlil_c3_lab_context_store_t *rx_store)
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
        &ctrl_hs, NINLIL_M4_LAB_ROLE_CONTROLLER, reg, provider, config);
    ctrl_hs.now_ms = 1000u;
    ninlil_m4_lab_handshake_init(
        &end_hs, NINLIL_M4_LAB_ROLE_ENDPOINT, reg, provider, config);
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
                tx_store, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_OK);
    (void)memset(&binding, 0, sizeof(binding));
    binding.site_domain_len = ctrl_hs.last_request.site_domain_len;
    (void)memcpy(binding.site_domain, ctrl_hs.last_request.site_domain, 16u);
    binding.attachment_id_len = ctrl_hs.last_request.device_stable_id_len;
    (void)memcpy(binding.attachment_id, ctrl_hs.last_request.device_stable_id, 32u);
    binding.initiator_stable_id_len = binding.attachment_id_len;
    (void)memcpy(binding.initiator_stable_id, binding.attachment_id, 32u);
    binding.responder_stable_id_len = config->controller_stable_id_len;
    (void)memcpy(
        binding.responder_stable_id, config->controller_stable_id, 32u);
    binding.membership_epoch = ctrl_hs.last_request.membership_epoch;
    binding.attachment_epoch = install_result.hop_context_id;
    binding.hop_context_id = install_result.hop_context_id;
    binding.session_id = ctrl_hs.active_session_id;
    binding.alloc_side = 2u;
    REQUIRE(ninlil_c3_lab_install_responder(
                rx_store,
                &binding,
                response.proof_hmac,
                ctrl_hs.challenge_nonce,
                &install_result)
        == NINLIL_C3_LAB_OK);
    return 0;
}

static int setup_r5_c6(
    ninlil_r5_object_t *r5obj,
    ninlil_r5_t **r5,
    ninlil_pcp_object_t *pcpobj,
    ninlil_pcp_t **pcp,
    ninlil_test_storage_t **storage,
    ninlil_test_clock_t **clock,
    ninlil_test_entropy_t **entropy,
    ninlil_c6_lab_object_t *c6obj,
    ninlil_c6_lab_t **c6)
{
    ninlil_test_storage_config_t cfg;
    ninlil_pcp_live_profile_t live;
    ninlil_pcp_instance_seed_t seed;
    ninlil_radio_hal_live_binding_t r5live;
    ninlil_r5_site_assignment_t assign;
    ninlil_r5_error_t err;
    ninlil_pcp_error_t pcp_err;
    uint8_t hw_doc[NINLIL_R5_HW_DOC_BYTES];
    uint8_t reg_doc[NINLIL_R5_REG_DOC_BYTES];

    (void)memcpy(hw_doc, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES);
    (void)memcpy(reg_doc, k_r5_golden_reg_v1, NINLIL_R5_REG_DOC_BYTES);
    make_assign(&assign);
    *r5obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    REQUIRE(ninlil_r5_init_object(r5obj, r5) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_hardware_profile(*r5, hw_doc, NINLIL_R5_HW_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_regulatory_profile(*r5, reg_doc, NINLIL_R5_REG_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_activate_profiles(*r5, &err) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_bind_site_assignment(*r5, &assign, &err) == NINLIL_R5_OK);
    *pcpobj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    REQUIRE(ninlil_pcp_init_object(pcpobj, pcp) == NINLIL_PCP_OK);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 64u;
    cfg.max_bytes_per_namespace = 65536u;
    *storage = ninlil_test_storage_create(&cfg);
    *clock = ninlil_test_clock_create();
    *entropy = ninlil_test_entropy_create(0xC509u, 1u);
    REQUIRE(*storage != NULL && *clock != NULL && *entropy != NULL);
    REQUIRE(
        ninlil_pcp_bind_storage(*pcp, ninlil_test_storage_ops(*storage), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_clock(*pcp, ninlil_test_clock_ops(*clock), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_entropy(*pcp, ninlil_test_entropy_ops(*entropy), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_build_live_binding(*r5, &r5live, &err) == NINLIL_R5_OK);
    live = r5live;
    REQUIRE(ninlil_pcp_bind_live_profile(*pcp, &live, &pcp_err) == NINLIL_PCP_OK);
    for (size_t i = 0u; i < 16u; ++i) {
        seed.bytes[i] = (uint8_t)(0x50u + (uint8_t)i);
    }
    REQUIRE(
        ninlil_pcp_publish_initial_meta(*pcp, &seed, &pcp_err) == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_bind_pcp(*r5, *pcp, &err) == NINLIL_R5_OK);
    *c6obj = (ninlil_c6_lab_object_t)NINLIL_C6_LAB_OBJECT_INIT;
    REQUIRE(ninlil_c6_lab_init_object(c6obj, *r5, c6, NULL) == NINLIL_C6_LAB_OK);
    return 0;
}

int main(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t config;
    ninlil_c3_lab_context_store_t tx_store;
    ninlil_c3_lab_context_store_t rx_store;
    ninlil_r5_object_t r5obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    ninlil_r5_t *r5;
    ninlil_pcp_object_t pcpobj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    ninlil_pcp_t *pcp;
    ninlil_test_storage_t *storage;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_c6_lab_object_t c6obj = (ninlil_c6_lab_object_t)NINLIL_C6_LAB_OBJECT_INIT;
    ninlil_c6_lab_t *c6;
    ninlil_c5_lab_radio_object_t radio_tx_obj = NINLIL_C5_LAB_RADIO_OBJECT_INIT;
    ninlil_c5_lab_radio_t *radio_tx;
    ninlil_c5_lab_radio_object_t radio_rx_obj = NINLIL_C5_LAB_RADIO_OBJECT_INIT;
    ninlil_c5_lab_radio_t *radio_rx;
    ninlil_c5_lab_radio_channel_t channel;
    static ninlil_c4_lab_usb_object_t ctrl_usb_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    static ninlil_c4_lab_usb_object_t cell_usb_obj = NINLIL_C4_LAB_USB_OBJECT_INIT;
    ninlil_c4_lab_usb_t *ctrl_usb;
    ninlil_c4_lab_usb_t *cell_usb;
    ninlil_c4_lab_usb_config_t usb_cfg;
    ninlil_fake_byte_stream_t ctrl_fake;
    ninlil_fake_byte_stream_t cell_fake;
    cookie_rng_ctx_t rng = {0xA9u};
    const uint8_t usb_payload[] = "runtime-usb-delivery";
    const uint8_t radio_payload[] = "runtime-radio-delivery";
    uint8_t recv[128];
    uint32_t recv_len = 0u;
    size_t radio_recv_len = 0u;
    ninlil_c4_c5_lab_dispatch_result_t disp;

    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&provider) == NINLIL_R7_CRYPTO_OK);
    m4_lab_fixture_seed_membership(&reg);
    m4_lab_fixture_site_config(&config);
    ninlil_c3_lab_context_store_init(&tx_store, &provider);
    ninlil_c3_lab_context_store_init(&rx_store, &provider);
    REQUIRE(install_radio_contexts(
                &provider, &reg, &config, &tx_store, &rx_store)
        == 0);
    REQUIRE(setup_r5_c6(
                &r5obj,
                &r5,
                &pcpobj,
                &pcp,
                &storage,
                &clock,
                &entropy,
                &c6obj,
                &c6)
        == 0);
    (void)pcp;
    (void)storage;
    (void)clock;
    (void)entropy;
    ninlil_c5_lab_radio_channel_init(&channel);
    REQUIRE(
        ninlil_c5_lab_radio_init_object(
            &radio_tx_obj, &tx_store, c6, &channel, &radio_tx)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(
        ninlil_c5_lab_radio_init_object(
            &radio_rx_obj, &rx_store, c6, &channel, &radio_rx)
        == NINLIL_C5_LAB_RADIO_OK);

    ninlil_fake_byte_stream_init(&ctrl_fake);
    ninlil_fake_byte_stream_init(&cell_fake);
    ninlil_fake_byte_stream_open_up(&ctrl_fake, 1u);
    ninlil_fake_byte_stream_open_up(&cell_fake, 2u);
    (void)memset(&usb_cfg, 0, sizeof(usb_cfg));
    usb_cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&ctrl_usb_obj, &usb_cfg, &ctrl_usb)
        == NINLIL_C4_LAB_USB_OK);
    usb_cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CELL;
    usb_cfg.cookie_rng = cookie_rng_cb;
    usb_cfg.cookie_rng_ctx = &rng;
    REQUIRE(
        ninlil_c4_lab_usb_init_object(&cell_usb_obj, &usb_cfg, &cell_usb)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind(ctrl_usb, &ctrl_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind(cell_usb, &cell_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind_peer(ctrl_usb, cell_usb) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(bring_up_usb(ctrl_usb, cell_usb, &ctrl_fake, &cell_fake) == 0);

    REQUIRE(
        ninlil_c4_c5_lab_dispatch_delivery(
            NINLIL_RT_V1_BEARER_ROUTE_U6,
            ctrl_usb,
            radio_tx,
            &channel,
            usb_payload,
            (uint32_t)sizeof(usb_payload) - 1u,
            0xC4C5u,
            &disp)
        == NINLIL_OK);
    REQUIRE(disp.usb_custody_ok == 1u);
    REQUIRE(
        ninlil_c4_lab_usb_custody_accept(
            cell_usb, 0xC4C5u, recv, sizeof(recv), &recv_len)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(recv_len == sizeof(usb_payload) - 1u);

    {
        ninlil_status_t radio_dispatch = ninlil_c4_c5_lab_dispatch_delivery(
            NINLIL_RT_V1_BEARER_ROUTE_SIMULATED,
            ctrl_usb,
            radio_tx,
            &channel,
            radio_payload,
            (uint32_t)sizeof(radio_payload) - 1u,
            0u,
            &disp);
        REQUIRE(radio_dispatch == NINLIL_OK);
    }
    REQUIRE(disp.radio_tx_ok == 1u);
    REQUIRE(disp.spi_tx_count >= 1u);
    REQUIRE(
        ninlil_c5_lab_radio_irq_rx_admit(
            radio_rx, recv, sizeof(recv), &radio_recv_len)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(radio_recv_len == sizeof(radio_payload) - 1u);
    REQUIRE(memcmp(recv, radio_payload, radio_recv_len) == 0);

    ninlil_test_storage_destroy(storage);
    ninlil_test_clock_destroy(clock);
    ninlil_test_entropy_destroy(entropy);
    (void)fprintf(stderr, "c4_c5_lab_path_e2e_test ok\n");
    return 0;
}
