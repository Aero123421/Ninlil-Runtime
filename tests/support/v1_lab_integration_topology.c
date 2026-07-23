/*
 * V1-LAB item 10b integration topology (test-only).
 */

#include "v1_lab_integration_topology.h"

#include "c3_lab_secure_wire.h"
#include "c4_c5_lab_wire.h"
#include "c4_lab_usb_path.h"
#include "c5_lab_radio_path.h"
#include "c6_lab_enforcement.h"
#include "c6_lab_spi_tx_sim.h"
#include "canonical_origin_authorization.h"
#include "deterministic_entropy.h"
#include "fake_byte_stream.h"
#include "in_memory_storage.h"
#include "m4_lab_credential_fixture.h"
#include "m4_lab_handshake.h"
#include "ninlil_posix_lab_platform.h"
#include "ninlil_posix_lab_platform_test.h"
#include "ninlil_posix_loopback_bearer_wire.h"
#include "profile_loader.h"
#include "profile_r5_golden_profiles.h"
#include "r7_crypto_openssl3.h"
#include "runtime_v1_capability.h"
#include "typed_simulated_bearer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "IG init fail %s:%d: %s\n", __FILE__, __LINE__, #c); \
            return 0;                                                          \
        }                                                                      \
    } while (0)

#define REQUIRE_STATUS(c)                                                      \
    do {                                                                       \
        if (!(c)) {                                                            \
            return -1;                                                         \
        }                                                                      \
    } while (0)

#define IG_MAX_STEPS 512u
#define IG_OWNERSHIP_TOKEN 0x1B10u

typedef struct cookie_rng_ctx {
    uint64_t seq;
} cookie_rng_ctx_t;

typedef struct v1_lab_c4_c5_bearer_inject v1_lab_c4_c5_bearer_inject_t;

struct v1_lab_integration_topology {
    char workdir[512];
    ninlil_r7_crypto_provider crypto;
    ninlil_m4_lab_membership_registry_t reg;
    ninlil_m4_lab_handshake_config_t m4_config;
    ninlil_c3_lab_context_store_t tx_store;
    ninlil_c3_lab_context_store_t rx_store;
    ninlil_r5_object_t r5obj;
    ninlil_r5_t *r5;
    ninlil_pcp_object_t pcpobj;
    ninlil_pcp_t *pcp;
    ninlil_test_storage_t *pcp_storage;
    ninlil_test_clock_t *pcp_clock;
    ninlil_test_entropy_t *pcp_entropy;
    ninlil_c6_lab_object_t c6obj;
    ninlil_c6_lab_t *c6;
    ninlil_c5_lab_radio_object_t ctrl_radio_obj;
    ninlil_c5_lab_radio_t *ctrl_radio;
    ninlil_c5_lab_radio_object_t end_radio_obj;
    ninlil_c5_lab_radio_t *end_radio;
    ninlil_c5_lab_radio_channel_t channel_fwd;
    ninlil_c5_lab_radio_channel_t channel_rev;
    ninlil_c4_lab_usb_object_t ctrl_usb_obj;
    ninlil_c4_lab_usb_object_t cell_usb_obj;
    ninlil_c4_lab_usb_t *ctrl_usb;
    ninlil_c4_lab_usb_t *cell_usb;
    ninlil_fake_byte_stream_t ctrl_fake;
    ninlil_fake_byte_stream_t cell_fake;
    ninlil_test_bearer_t *shared_bearer;
    v1_lab_c4_c5_bearer_inject_t *bearer_inject;
    ninlil_posix_lab_platform_t *ctrl_platform;
    ninlil_posix_lab_platform_t *end_platform;
    ninlil_id128_t ctrl_runtime_id;
    ninlil_id128_t end_runtime_id;
    uint8_t replay_frame[NINLIL_C3_LAB_WIRE_FRAME_MAX];
    uint32_t replay_frame_len;
    uint32_t inject_mode;
    uint32_t inject_drop_budget;
    uint32_t inject_dup_budget;
    uint32_t inject_drops_used;
    uint32_t inject_dups_used;
    uint32_t transport_drop_data;
    uint32_t transport_drop_ack;
    uint32_t transport_crc_fault;
    uint32_t transport_auth_fault;
    uint32_t storage_fault_armed;
    uint32_t replay_injected;
    uint64_t spi_tx_before;
    uint64_t usb_now_ms;
    uint64_t next_clock_ms;
    uint64_t bearer_clock_ms;
};

struct v1_lab_c4_c5_bearer_inject {
    v1_lab_integration_topology_t *topology;
    ninlil_test_bearer_t *inner;
    ninlil_bearer_ops_t bearer_ops;
    ninlil_tx_gate_ops_t tx_gate_ops;
    uint64_t send_count;
    uint64_t recv_count;
    uint64_t drop_count;
};

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

static void set_id(ninlil_id128_t *id, uint8_t tag)
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t value)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = value;
}

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static int id_equal_local(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static void pump_usb_bytes(v1_lab_integration_topology_t *topo)
{
    uint8_t buf[2048];
    uint32_t n;

    n = ninlil_fake_byte_stream_take_tx(&topo->ctrl_fake, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(&topo->cell_fake, buf, n);
    }
    n = ninlil_fake_byte_stream_take_tx(&topo->cell_fake, buf, sizeof(buf));
    if (n > 0u) {
        (void)ninlil_fake_byte_stream_inject_rx(&topo->ctrl_fake, buf, n);
    }
}

static void pump_usb(v1_lab_integration_topology_t *topo)
{
    pump_usb_bytes(topo);
    (void)ninlil_c4_lab_usb_step(topo->ctrl_usb, topo->usb_now_ms, 50u);
    (void)ninlil_c4_lab_usb_step(topo->cell_usb, topo->usb_now_ms, 50u);
    topo->usb_now_ms += 10u;
}

static int bring_up_usb(v1_lab_integration_topology_t *topo)
{
    uint32_t i;

    topo->usb_now_ms = 5000u;
    for (i = 0u; i < 200u; ++i) {
        pump_usb(topo);
        if (ninlil_c4_lab_usb_session_active(topo->ctrl_usb) != 0
            && ninlil_c4_lab_usb_session_active(topo->cell_usb) != 0) {
            return 1;
        }
    }
    return 0;
}

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
    a->site_assignment_rev = 4u;
    a->site_assignment_epoch = 9u;
    a->controller_term = 11u;
    fill_digest(a->assignment_digest, 0x50u);
    a->permit_bind_generation = 3u;
    fill_id(&a->transmitter_id, 0x40u);
    a->channel_id = 2u;
    a->phy.bandwidth_hz = 125000u;
    a->phy.spreading_factor = 7u;
    a->phy.coding_rate_denom = 5u;
    a->phy.preamble_symbols = 8u;
    a->phy.tx_power_mdb = 10000;
    a->phy.phy_flags = 0u;
}

static int install_contexts(v1_lab_integration_topology_t *topo)
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
        &ctrl_hs, NINLIL_M4_LAB_ROLE_CONTROLLER, &topo->reg, &topo->crypto, &topo->m4_config);
    ctrl_hs.now_ms = 1000u;
    ninlil_m4_lab_handshake_init(
        &end_hs, NINLIL_M4_LAB_ROLE_ENDPOINT, &topo->reg, &topo->crypto, &topo->m4_config);
    end_hs.now_ms = 1000u;
    REQUIRE(ninlil_m4_lab_handshake_endpoint_begin(&end_hs, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_request(
                &ctrl_hs, step.out_frame, step.out_frame_len, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_handshake_endpoint_on_challenge(
                &end_hs, step.out_frame, step.out_frame_len, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_m4_lab_decode_join_response(
                step.out_frame, step.out_frame_len, &response)
        == NINLIL_M4_LAB_OK);
    REQUIRE(ninlil_m4_lab_handshake_controller_on_response(
                &ctrl_hs, step.out_frame, step.out_frame_len, &endpoint_cred, &step)
        == NINLIL_M4_LAB_OK);
    REQUIRE(step.success != 0);
    REQUIRE(ninlil_c3_lab_install_from_token(
                &topo->tx_store, &ctrl_hs.install_token, &install_result)
        == NINLIL_C3_LAB_OK);
    (void)memset(&binding, 0, sizeof(binding));
    binding.site_domain_len = ctrl_hs.last_request.site_domain_len;
    (void)memcpy(binding.site_domain, ctrl_hs.last_request.site_domain, 16u);
    binding.attachment_id_len = ctrl_hs.last_request.device_stable_id_len;
    (void)memcpy(binding.attachment_id, ctrl_hs.last_request.device_stable_id, 32u);
    binding.initiator_stable_id_len = binding.attachment_id_len;
    (void)memcpy(binding.initiator_stable_id, binding.attachment_id, 32u);
    binding.responder_stable_id_len = topo->m4_config.controller_stable_id_len;
    (void)memcpy(
        binding.responder_stable_id, topo->m4_config.controller_stable_id, 32u);
    binding.membership_epoch = ctrl_hs.last_request.membership_epoch;
    binding.attachment_epoch = install_result.hop_context_id;
    binding.hop_context_id = install_result.hop_context_id;
    binding.session_id = ctrl_hs.active_session_id;
    binding.alloc_side = 2u;
    REQUIRE(ninlil_c3_lab_install_responder(
                &topo->rx_store,
                &binding,
                response.proof_hmac,
                ctrl_hs.challenge_nonce,
                &install_result)
        == NINLIL_C3_LAB_OK);
    return 1;
}

static int setup_r5_c6(v1_lab_integration_topology_t *topo)
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
    topo->r5obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    REQUIRE(ninlil_r5_init_object(&topo->r5obj, &topo->r5) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_load_hardware_profile(
                topo->r5, hw_doc, NINLIL_R5_HW_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_load_regulatory_profile(
                topo->r5, reg_doc, NINLIL_R5_REG_DOC_BYTES, &err)
        == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_activate_profiles(topo->r5, &err) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_bind_site_assignment(topo->r5, &assign, &err) == NINLIL_R5_OK);
    topo->pcpobj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    REQUIRE(ninlil_pcp_init_object(&topo->pcpobj, &topo->pcp) == NINLIL_PCP_OK);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 64u;
    cfg.max_bytes_per_namespace = 65536u;
    topo->pcp_storage = ninlil_test_storage_create(&cfg);
    topo->pcp_clock = ninlil_test_clock_create();
    topo->pcp_entropy = ninlil_test_entropy_create(0xC509u, 1u);
    REQUIRE(topo->pcp_storage != NULL && topo->pcp_clock != NULL
        && topo->pcp_entropy != NULL);
    REQUIRE(ninlil_pcp_bind_storage(
                topo->pcp, ninlil_test_storage_ops(topo->pcp_storage), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_pcp_bind_clock(
                topo->pcp, ninlil_test_clock_ops(topo->pcp_clock), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_pcp_bind_entropy(
                topo->pcp, ninlil_test_entropy_ops(topo->pcp_entropy), &pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_build_live_binding(topo->r5, &r5live, &err) == NINLIL_R5_OK);
    live = r5live;
    REQUIRE(ninlil_pcp_bind_live_profile(topo->pcp, &live, &pcp_err) == NINLIL_PCP_OK);
    for (size_t i = 0u; i < 16u; ++i) {
        seed.bytes[i] = (uint8_t)(0x50u + (uint8_t)i);
    }
    REQUIRE(ninlil_pcp_publish_initial_meta(topo->pcp, &seed, &pcp_err) == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_bind_pcp(topo->r5, topo->pcp, &err) == NINLIL_R5_OK);
    topo->c6obj = (ninlil_c6_lab_object_t)NINLIL_C6_LAB_OBJECT_INIT;
    REQUIRE(ninlil_c6_lab_init_object(&topo->c6obj, topo->r5, &topo->c6, NULL)
        == NINLIL_C6_LAB_OK);
    return 1;
}

#define IG_COMPACT_MAGIC 0x31474976u

typedef struct ig_compact_wire {
    uint32_t magic;
    uint32_t kind;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t source_runtime_id;
    ninlil_id128_t target_runtime_id;
    ninlil_digest256_t content_digest;
    uint64_t generation;
    uint64_t effect_deadline_ms;
} ig_compact_wire_t;

static int compact_wire_encode(
    const ninlil_bearer_message_t *message,
    uint8_t *out_buf,
    size_t out_capacity,
    size_t *out_len)
{
    ig_compact_wire_t wire;

    if (message == NULL || out_buf == NULL || out_len == NULL
        || out_capacity < sizeof(wire)) {
        return 0;
    }
    (void)memset(&wire, 0, sizeof(wire));
    wire.magic = IG_COMPACT_MAGIC;
    wire.kind = (uint32_t)message->kind;
    wire.transaction_id = message->transaction_id;
    wire.attempt_id = message->attempt_id;
    wire.source_runtime_id = message->source.runtime_id;
    wire.target_runtime_id = message->target.target_runtime_id;
    wire.content_digest = message->content_digest;
    wire.generation = message->generation;
    wire.effect_deadline_ms = message->absolute_effect_deadline_ms;
    (void)memcpy(out_buf, &wire, sizeof(wire));
    *out_len = sizeof(wire);
    return 1;
}

static void set_text_id(ninlil_text_id_t *id, const char *text)
{
    size_t len;

    if (id == NULL || text == NULL) {
        return;
    }
    len = strlen(text);
    if (len > sizeof(id->bytes)) {
        len = sizeof(id->bytes);
    }
    id->length = (uint8_t)len;
    if (len > 0u) {
        (void)memcpy(id->bytes, text, len);
    }
}

static int compact_wire_decode(
    v1_lab_integration_topology_t *topo,
    const uint8_t *wire_buf,
    size_t wire_len,
    ninlil_bearer_message_t *out_message)
{
    const ig_compact_wire_t *wire;
    static const char NS_TEXT[] = "org.ninlil.examples";
    static const char SVC_TEXT[] = "absolute-state";
    int from_ctrl;

    if (topo == NULL || wire_buf == NULL || out_message == NULL
        || wire_len < sizeof(*wire)) {
        return 0;
    }
    wire = (const ig_compact_wire_t *)(const void *)wire_buf;
    if (wire->magic != IG_COMPACT_MAGIC) {
        return 0;
    }
    from_ctrl = id_equal_local(&wire->source_runtime_id, &topo->ctrl_runtime_id);
    (void)memset(out_message, 0, sizeof(*out_message));
    set_header(&out_message->abi_version, &out_message->struct_size, sizeof(*out_message));
    out_message->kind = (ninlil_bearer_message_kind_t)wire->kind;
    out_message->transaction_id = wire->transaction_id;
    out_message->attempt_id = wire->attempt_id;
    out_message->content_digest = wire->content_digest;
    out_message->generation = wire->generation;
    out_message->absolute_effect_deadline_ms = wire->effect_deadline_ms;
    out_message->required_evidence = NINLIL_EVIDENCE_APPLIED;
    set_header(
        &out_message->source.abi_version,
        &out_message->source.struct_size,
        sizeof(out_message->source));
    out_message->source.runtime_id = wire->source_runtime_id;
    set_id(&out_message->source.application_instance_id, from_ctrl != 0 ? 0x70u : 0x81u);
    set_header(
        &out_message->source.local_identity.abi_version,
        &out_message->source.local_identity.struct_size,
        sizeof(out_message->source.local_identity));
    out_message->source.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(
        &out_message->source.local_identity.device_id,
        from_ctrl != 0 ? 0x20u : 0x31u);
    set_id(
        &out_message->source.local_identity.installation_id,
        from_ctrl != 0 ? 0x30u : 0x41u);
    set_id(
        &out_message->source.local_identity.site_domain_id,
        from_ctrl != 0 ? 0x40u : 0x51u);
    out_message->source.local_identity.binding_epoch = 1u;
    out_message->source.local_identity.membership_epoch = 1u;
    set_header(
        &out_message->target.abi_version,
        &out_message->target.struct_size,
        sizeof(out_message->target));
    out_message->target.target_runtime_id = wire->target_runtime_id;
    set_id(
        &out_message->target.target_application_instance_id,
        id_equal_local(&wire->target_runtime_id, &topo->end_runtime_id) != 0
            ? 0x81u
            : 0x70u);
    set_header(
        &out_message->service.abi_version,
        &out_message->service.struct_size,
        sizeof(out_message->service));
    set_text_id(&out_message->service.namespace_id, NS_TEXT);
    set_text_id(&out_message->service.service_id, SVC_TEXT);
    set_text_id(&out_message->service.schema_id, SVC_TEXT);
    out_message->service.schema_major = 1u;
    out_message->service.family = NINLIL_FAMILY_DESIRED_STATE;
    return 1;
}

static int transport_wire(
    v1_lab_integration_topology_t *topo,
    int from_ctrl,
    const uint8_t *wire,
    size_t wire_len,
    ninlil_bearer_message_t *out_message)
{
    ninlil_c4_c5_lab_dispatch_result_t disp;
    uint8_t recv_buf[4096];
    uint32_t recv_len = 0u;
    size_t radio_len = 0u;
    ninlil_c5_lab_radio_status_t radio_st;
    ninlil_bearer_message_t decoded_msg;
    ninlil_status_t dispatch_st;

    if (from_ctrl != 0) {
        if (topo->transport_drop_data != 0u
            && topo->inject_drops_used < topo->inject_drop_budget) {
            topo->inject_drops_used += 1u;
            if (topo->inject_mode != V1_LAB_IG_SCENARIO_TIMEOUT) {
                topo->transport_drop_data = 0u;
            }
            return 0;
        }
        dispatch_st = ninlil_c4_c5_lab_dispatch_delivery(
            NINLIL_RT_V1_BEARER_ROUTE_U6,
            topo->ctrl_usb,
            topo->ctrl_radio,
            &topo->channel_fwd,
            wire,
            (uint32_t)wire_len,
            IG_OWNERSHIP_TOKEN,
            &disp);
        if (dispatch_st != NINLIL_OK || disp.usb_custody_ok == 0u) {
            return 0;
        }
        pump_usb(topo);
        if (ninlil_c4_lab_usb_custody_accept(
                topo->cell_usb,
                IG_OWNERSHIP_TOKEN,
                recv_buf,
                sizeof(recv_buf),
                &recv_len)
            != NINLIL_C4_LAB_USB_OK) {
            return 0;
        }
        if (recv_len != wire_len || memcmp(recv_buf, wire, wire_len) != 0) {
            return 0;
        }
        if (topo->transport_crc_fault != 0u) {
            recv_buf[0] ^= 0xFFu;
        }
        if (topo->transport_auth_fault != 0u && wire_len > 8u) {
            recv_buf[8] ^= 0xAAu;
        }
        radio_st = ninlil_c5_lab_radio_tx_data(
            topo->ctrl_radio, recv_buf, recv_len, &topo->channel_fwd);
        if (topo->transport_auth_fault != 0u || topo->transport_crc_fault != 0u) {
            return 0;
        }
        if (radio_st != NINLIL_C5_LAB_RADIO_OK) {
            return 0;
        }
        if (topo->inject_mode == V1_LAB_IG_SCENARIO_DATA_DUPLICATE
            && topo->inject_dups_used < topo->inject_dup_budget) {
            (void)ninlil_c5_lab_radio_channel_deliver(
                &topo->channel_fwd, recv_buf, recv_len);
            topo->inject_dups_used += 1u;
        }
        if (topo->inject_mode == V1_LAB_IG_SCENARIO_REORDER_REPLAY
            && topo->replay_frame_len > 0u) {
            (void)ninlil_c5_lab_radio_channel_deliver(
                &topo->channel_fwd, topo->replay_frame, topo->replay_frame_len);
            topo->replay_injected += 1u;
        }
    } else {
        if (topo->transport_drop_ack != 0u
            && topo->inject_drops_used < topo->inject_drop_budget) {
            topo->inject_drops_used += 1u;
            topo->transport_drop_ack = 0u;
            return 0;
        }
        radio_st = ninlil_c5_lab_radio_tx_data(
            topo->end_radio, wire, wire_len, &topo->channel_rev);
        if (radio_st != NINLIL_C5_LAB_RADIO_OK) {
            return 0;
        }
    }

    radio_st = from_ctrl != 0
        ? ninlil_c5_lab_radio_irq_rx_admit(
              topo->end_radio, recv_buf, sizeof(recv_buf), &radio_len)
        : ninlil_c5_lab_radio_irq_rx_admit(
              topo->ctrl_radio, recv_buf, sizeof(recv_buf), &radio_len);
    if (radio_st == NINLIL_C5_LAB_RADIO_REPLAY
        || radio_st == NINLIL_C5_LAB_RADIO_AUTH_FAILED
        || radio_st == NINLIL_C5_LAB_RADIO_FIFO_EMPTY) {
        return 0;
    }
    if (radio_st != NINLIL_C5_LAB_RADIO_OK) {
        return 0;
    }
    if (from_ctrl != 0 && topo->replay_frame_len == 0u && radio_len <= sizeof(topo->replay_frame)) {
        topo->replay_frame_len = (uint32_t)radio_len;
        (void)memcpy(topo->replay_frame, recv_buf, radio_len);
    }
    if (!compact_wire_decode(topo, recv_buf, radio_len, &decoded_msg)) {
        return 0;
    }
    *out_message = decoded_msg;
    return 1;
}

static int inject_transport(
    v1_lab_c4_c5_bearer_inject_t *inject,
    const ninlil_id128_t *from_runtime_id,
    const ninlil_bearer_message_t *message)
{
    v1_lab_integration_topology_t *topo = inject->topology;
    uint8_t wire_buf[sizeof(ig_compact_wire_t)];
    size_t wire_len = 0u;
    ninlil_bearer_message_t delivered;
    int from_ctrl;
    ninlil_id128_t peer_id;

    (void)memset(&delivered, 0, sizeof(delivered));
    from_ctrl = id_equal_local(from_runtime_id, &topo->ctrl_runtime_id);
    if (!compact_wire_encode(message, wire_buf, sizeof(wire_buf), &wire_len)) {
        return 0;
    }
    if (!transport_wire(topo, from_ctrl, wire_buf, wire_len, &delivered)) {
        return 0;
    }
    peer_id = from_ctrl != 0 ? topo->end_runtime_id : topo->ctrl_runtime_id;
    return ninlil_test_bearer_deliver_to_runtime(
        inject->inner, &peer_id, &delivered);
}

static ninlil_bearer_status_t inject_open(
    void *user,
    const ninlil_id128_t *runtime_id,
    ninlil_role_t role,
    ninlil_bearer_handle_t *out_handle)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    return ninlil_test_bearer_ops(inject->inner)->open(
        inject->inner, runtime_id, role, out_handle);
}

static void inject_close(void *user, ninlil_bearer_handle_t handle)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    ninlil_test_bearer_ops(inject->inner)->close(inject->inner, handle);
}

static int abi_header_valid(uint16_t version, uint16_t size, size_t expected)
{
    return version == NINLIL_ABI_VERSION && size == (uint16_t)expected;
}

static void normalize_bearer_message(
    v1_lab_integration_topology_t *topo,
    ninlil_bearer_message_t *message)
{
    if (topo == NULL || message == NULL) {
        return;
    }
    if (!abi_header_valid(
            message->abi_version, message->struct_size, sizeof(*message))) {
        set_header(&message->abi_version, &message->struct_size, sizeof(*message));
    }
    if (!abi_header_valid(
            message->source.abi_version,
            message->source.struct_size,
            sizeof(message->source))) {
        set_header(
            &message->source.abi_version,
            &message->source.struct_size,
            sizeof(message->source));
    }
    if (!abi_header_valid(
            message->source.local_identity.abi_version,
            message->source.local_identity.struct_size,
            sizeof(message->source.local_identity))) {
        set_header(
            &message->source.local_identity.abi_version,
            &message->source.local_identity.struct_size,
            sizeof(message->source.local_identity));
        message->source.local_identity.flags =
            NINLIL_LOCAL_IDENTITY_HAS_DEVICE
            | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
            | NINLIL_LOCAL_IDENTITY_HAS_SITE;
        if (id_equal_local(&message->source.runtime_id, &topo->ctrl_runtime_id)) {
            set_id(&message->source.local_identity.device_id, 0x20u);
            set_id(&message->source.local_identity.installation_id, 0x30u);
            set_id(&message->source.local_identity.site_domain_id, 0x40u);
        } else {
            set_id(&message->source.local_identity.device_id, 0x31u);
            set_id(&message->source.local_identity.installation_id, 0x41u);
            set_id(&message->source.local_identity.site_domain_id, 0x51u);
        }
        message->source.local_identity.binding_epoch = 1u;
        message->source.local_identity.membership_epoch = 1u;
    }
    if (!abi_header_valid(
            message->target.abi_version,
            message->target.struct_size,
            sizeof(message->target))) {
        set_header(
            &message->target.abi_version,
            &message->target.struct_size,
            sizeof(message->target));
        if (id_equal_local(&message->source.runtime_id, &topo->ctrl_runtime_id)) {
            set_id(&message->target.target_runtime_id, 0x21u);
            set_id(&message->target.target_application_instance_id, 0x81u);
        } else {
            set_id(&message->target.target_runtime_id, 0x10u);
            set_id(&message->target.target_application_instance_id, 0x70u);
        }
    }
    if (!abi_header_valid(
            message->service.abi_version,
            message->service.struct_size,
            sizeof(message->service))) {
        set_header(
            &message->service.abi_version,
            &message->service.struct_size,
            sizeof(message->service));
    }
}

static ninlil_bearer_status_t inject_send(
    void *user,
    ninlil_bearer_handle_t handle,
    const ninlil_tx_permit_t *permit,
    const ninlil_bearer_message_t *message,
    ninlil_bearer_send_result_t *out_result)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    ninlil_bearer_status_t status;
    ninlil_id128_t from_id;
    ninlil_bearer_message_t normalized;

    if (message == NULL) {
        return NINLIL_BEARER_DENIED;
    }
    normalized = *message;
    normalize_bearer_message(inject->topology, &normalized);
    message = &normalized;
    if (inject->topology->inject_mode == V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED
        && message->kind == NINLIL_BEARER_MESSAGE_APPLICATION) {
        inject->drop_count += 1u;
        (void)memset(out_result, 0, sizeof(*out_result));
        out_result->abi_version = NINLIL_ABI_VERSION;
        out_result->struct_size = (uint16_t)sizeof(*out_result);
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    from_id = message->source.runtime_id;
    status = ninlil_test_bearer_integration_gate_send(
        inject->inner, handle, permit, message, out_result);
    if (status != NINLIL_BEARER_OK) {
        return status;
    }
    if (!inject_transport(inject, &from_id, message)) {
        return NINLIL_BEARER_WOULD_BLOCK;
    }
    inject->send_count += 1u;
    return NINLIL_BEARER_OK;
}

static ninlil_bearer_status_t inject_receive(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *out_message)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    ninlil_bearer_status_t status;

    status = ninlil_test_bearer_ops(inject->inner)->receive_next(
        inject->inner, handle, out_message);
    if (status == NINLIL_BEARER_OK) {
        inject->recv_count += 1u;
        if (inject->topology->transport_drop_ack != 0u
            && out_message->kind == NINLIL_BEARER_MESSAGE_RECEIPT) {
            ninlil_test_bearer_ops(inject->inner)->release_received(
                inject->inner, handle, out_message);
            return NINLIL_BEARER_EMPTY;
        }
    }
    return status;
}

static void inject_release(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_message_t *message)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    ninlil_test_bearer_ops(inject->inner)->release_received(
        inject->inner, handle, message);
}

static ninlil_bearer_status_t inject_state(
    void *user,
    ninlil_bearer_handle_t handle,
    ninlil_bearer_state_t *out_state)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    return ninlil_test_bearer_ops(inject->inner)->state(
        inject->inner, handle, out_state);
}

static ninlil_tx_gate_status_t inject_tx_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    static uint32_t acquire_log;
    ninlil_tx_gate_status_t status = ninlil_test_bearer_tx_gate_ops(inject->inner)->acquire(
        inject->inner, request, now, out_permit);
    (void)acquire_log;
    return status;
}

static void inject_tx_release(void *user, const ninlil_tx_permit_t *permit)
{
    v1_lab_c4_c5_bearer_inject_t *inject = (v1_lab_c4_c5_bearer_inject_t *)user;
    ninlil_test_bearer_tx_gate_ops(inject->inner)->release_unused(
        inject->inner, permit);
}

static v1_lab_c4_c5_bearer_inject_t *bearer_inject_create(
    v1_lab_integration_topology_t *topo,
    ninlil_test_bearer_t *inner)
{
    v1_lab_c4_c5_bearer_inject_t *inject;

    inject = (v1_lab_c4_c5_bearer_inject_t *)calloc(1u, sizeof(*inject));
    if (inject == NULL) {
        return NULL;
    }
    inject->topology = topo;
    inject->inner = inner;
    inject->bearer_ops.abi_version = NINLIL_ABI_VERSION;
    inject->bearer_ops.struct_size = (uint16_t)sizeof(inject->bearer_ops);
    inject->bearer_ops.user = inject;
    inject->bearer_ops.open = inject_open;
    inject->bearer_ops.close = inject_close;
    inject->bearer_ops.send = inject_send;
    inject->bearer_ops.receive_next = inject_receive;
    inject->bearer_ops.release_received = inject_release;
    inject->bearer_ops.state = inject_state;
    inject->tx_gate_ops.abi_version = NINLIL_ABI_VERSION;
    inject->tx_gate_ops.struct_size = (uint16_t)sizeof(inject->tx_gate_ops);
    inject->tx_gate_ops.user = inject;
    inject->tx_gate_ops.acquire = inject_tx_acquire;
    inject->tx_gate_ops.release_unused = inject_tx_release;
    return inject;
}

static ninlil_runtime_config_t runtime_config(
    ninlil_role_t role,
    const uint8_t *storage_ns,
    size_t storage_ns_len,
    uint8_t runtime_tag)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_tag);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_tag + 0x10u));
    set_id(&config.local_identity.installation_id, (uint8_t)(runtime_tag + 0x20u));
    set_id(&config.local_identity.site_domain_id, (uint8_t)(runtime_tag + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_ns;
    config.storage_namespace.length = storage_ns_len;
    set_header(&config.limits.abi_version, &config.limits.struct_size, sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1000u;
    config.limits.max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 5000u : 0u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 3u;
    config.limits.max_retained_terminal_transactions = 16u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_event_spool_count = role == NINLIL_ROLE_ENDPOINT ? 32u : 0u;
    config.limits.max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 32768u : 0u;
    config.limits.max_result_cache_entries = 16u;
    config.limits.max_retained_dispositions = 16u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 4242u;
    config.result_cache_retention_ms = 2000u;
    config.observation_retention_ms = 800u;
    return config;
}

static ninlil_service_descriptor_t desired_descriptor(uint8_t app_tag)
{
    ninlil_service_descriptor_t descriptor;
    static const char NS_TEXT[] = "org.ninlil.examples";

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(&descriptor.abi_version, &descriptor.struct_size, sizeof(descriptor));
    descriptor.namespace_id.data = (const uint8_t *)NS_TEXT;
    descriptor.namespace_id.length = sizeof(NS_TEXT) - 1u;
    descriptor.service_id.data = (const uint8_t *)"absolute-state";
    descriptor.service_id.length = sizeof("absolute-state") - 1u;
    descriptor.schema_id.data = (const uint8_t *)"absolute-state";
    descriptor.schema_id.length = sizeof("absolute-state") - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x11u);
    set_id(&descriptor.local_application_instance_id, app_tag);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 1000u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 5000u;
    descriptor.maximum_deadline_ms = 5000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    return descriptor;
}

static uint32_t g_delivery_calls;
static uint32_t g_outcome_satisfied;

static ninlil_reconcile_action_t endpoint_reconcile_cb(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

static ninlil_callback_action_t endpoint_delivery_cb(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    (void)user;
    (void)token;
    (void)delivery;
    g_delivery_calls += 1u;
    out_sync_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_sync_result->evidence_stage = NINLIL_EVIDENCE_APPLIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static void configure_inject(v1_lab_integration_topology_t *topo, uint32_t scenario)
{
    topo->inject_mode = scenario;
    topo->inject_drop_budget = 1u;
    topo->inject_dup_budget = 1u;
    topo->inject_drops_used = 0u;
    topo->inject_dups_used = 0u;
    topo->transport_drop_data = 0u;
    topo->transport_drop_ack = 0u;
    topo->transport_crc_fault = 0u;
    topo->transport_auth_fault = 0u;
    topo->storage_fault_armed = 0u;
    topo->replay_frame_len = 0u;
    topo->replay_injected = 0u;
    switch (scenario) {
    case V1_LAB_IG_SCENARIO_ACK_LOSS:
        topo->transport_drop_ack = 1u;
        break;
    case V1_LAB_IG_SCENARIO_DATA_DUPLICATE:
        topo->inject_dup_budget = 1u;
        break;
    case V1_LAB_IG_SCENARIO_REORDER_REPLAY:
        break;
    case V1_LAB_IG_SCENARIO_TIMEOUT:
        topo->transport_drop_data = 1u;
        topo->inject_drop_budget = 4096u;
        break;
    case V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED:
        break;
    case V1_LAB_IG_SCENARIO_CRC_FAULT:
        topo->transport_crc_fault = 1u;
        break;
    case V1_LAB_IG_SCENARIO_AUTH_FAULT:
        topo->transport_auth_fault = 1u;
        break;
    case V1_LAB_IG_SCENARIO_STORAGE_FAULT:
        topo->storage_fault_armed = 1u;
        break;
    default:
        break;
    }
}

static int corrupt_db(const char *path)
{
    FILE *fp = fopen(path, "r+b");
    if (fp == NULL) {
        return 0;
    }
    (void)fseek(fp, 16, SEEK_SET);
    {
        static const uint8_t garbage[8] = {0};
        if (fwrite(garbage, 1, sizeof(garbage), fp) != sizeof(garbage)) {
            (void)fclose(fp);
            return 0;
        }
    }
    (void)fclose(fp);
    return 1;
}

static int advance_all_clocks(v1_lab_integration_topology_t *topo, uint64_t delta_ms)
{
    ninlil_test_clock_t *clock;
    ninlil_time_sample_t sample;
    const ninlil_platform_ops_t *ops;

    if (topo == NULL || delta_ms == 0u || topo->ctrl_platform == NULL) {
        return 0;
    }
    clock = ninlil_posix_lab_platform_test_clock(topo->ctrl_platform);
    if (clock == NULL || !ninlil_test_clock_advance(clock, delta_ms)) {
        return 0;
    }
    clock = ninlil_posix_lab_platform_test_clock(topo->end_platform);
    if (clock == NULL || !ninlil_test_clock_advance(clock, delta_ms)) {
        return 0;
    }
    ops = ninlil_posix_lab_platform_ops(topo->ctrl_platform);
    if (ops == NULL || ops->clock == NULL || ops->clock->now == NULL) {
        return 0;
    }
    if (ops->clock->now(ops->clock->user, &sample) != NINLIL_PORT_OK) {
        return 0;
    }
    if (!ninlil_test_bearer_set_time(
            topo->shared_bearer, sample.clock_epoch_id, sample.now_ms)) {
        return 0;
    }
    topo->bearer_clock_ms = sample.now_ms;
    return 1;
}

static int align_scenario_clocks(v1_lab_integration_topology_t *topo)
{
    ninlil_test_clock_t *clock;
    ninlil_id128_t epoch;

    if (topo == NULL || topo->ctrl_platform == NULL || topo->shared_bearer == NULL) {
        return 0;
    }
    (void)memset(&epoch, 0, sizeof(epoch));
    epoch.bytes[0] = 0xa0u;
    epoch.bytes[15] = 0x01u;
    if (topo->next_clock_ms <= topo->bearer_clock_ms) {
        topo->next_clock_ms = topo->bearer_clock_ms + 1000u;
    }
    if (topo->next_clock_ms == 0u) {
        topo->next_clock_ms = 1000u;
    }
    clock = ninlil_posix_lab_platform_test_clock(topo->ctrl_platform);
    if (clock == NULL || !ninlil_test_clock_advance(clock, topo->next_clock_ms)) {
        return 0;
    }
    clock = ninlil_posix_lab_platform_test_clock(topo->end_platform);
    if (clock == NULL || !ninlil_test_clock_advance(clock, topo->next_clock_ms)) {
        return 0;
    }
    if (!ninlil_test_bearer_set_time(topo->shared_bearer, epoch, topo->next_clock_ms)) {
        return 0;
    }
    topo->bearer_clock_ms = topo->next_clock_ms;
    topo->next_clock_ms += 10000u;
    return 1;
}

static int run_single_scenario(
    v1_lab_integration_topology_t *topo,
    uint32_t scenario,
    v1_lab_integration_scenario_result_t *out_result)
{
    static const uint8_t CTRL_NS[] = "v1-ig-ctrl";
    static const uint8_t END_NS[] = "v1-ig-end";
    static const uint8_t idem_key[] = "integration-gate-idem";
    char ctrl_db[576];
    char end_db[576];
    ninlil_posix_lab_platform_config_t pcfg;
    ninlil_runtime_config_t ctrl_cfg;
    ninlil_runtime_config_t end_cfg;
    ninlil_model_runtime_validation_result_t validation;
    ninlil_runtime_t *ctrl_rt = NULL;
    ninlil_runtime_t *end_rt = NULL;
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_service_t *ctrl_svc = NULL;
    ninlil_service_t *end_svc = NULL;
    ninlil_submission_t submission;
    ninlil_submission_result_t submit_result;
    ninlil_concrete_target_t target;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    uint8_t payload[16];
    uint32_t step;
    int ctrl_restarted = 0;
    int end_restarted = 0;
    ninlil_c5_lab_radio_stats_t stats_before;
    ninlil_c5_lab_radio_stats_t stats_after;
    ninlil_c5_lab_radio_stats_t ctrl_stats_before;
    ninlil_c5_lab_radio_stats_t ctrl_stats_after;

#define SCENARIO_REQUIRE(c)                                                    \
    do {                                                                       \
        if (!(c)) {                                                            \
            goto scenario_fail;                                                \
        }                                                                      \
    } while (0)

    g_delivery_calls = 0u;
    g_outcome_satisfied = 0u;
    configure_inject(topo, scenario);
    if (topo->ctrl_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->ctrl_platform);
        topo->ctrl_platform = NULL;
    }
    if (topo->end_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->end_platform);
        topo->end_platform = NULL;
    }
    if (topo->bearer_inject != NULL) {
        topo->bearer_inject->send_count = 0u;
        topo->bearer_inject->recv_count = 0u;
        topo->bearer_inject->drop_count = 0u;
    }
    SCENARIO_REQUIRE(snprintf(ctrl_db, sizeof(ctrl_db), "%s/ig-ctrl-%u.db", topo->workdir, scenario) > 0);
    SCENARIO_REQUIRE(snprintf(end_db, sizeof(end_db), "%s/ig-end-%u.db", topo->workdir, scenario) > 0);
    (void)unlink(ctrl_db);
    (void)unlink(end_db);

    ninlil_posix_lab_platform_config_defaults(&pcfg);
    pcfg.database_path = ctrl_db;
    pcfg.role = NINLIL_ROLE_CONTROLLER;
    pcfg.bearer_kind = NINLIL_POSIX_LAB_PLATFORM_BEARER_SIMULATED;
    topo->ctrl_platform = ninlil_posix_lab_platform_create(&pcfg);
    SCENARIO_REQUIRE(topo->ctrl_platform != NULL);
    pcfg.database_path = end_db;
    pcfg.role = NINLIL_ROLE_ENDPOINT;
    topo->end_platform = ninlil_posix_lab_platform_create(&pcfg);
    SCENARIO_REQUIRE(topo->end_platform != NULL);
    ninlil_posix_lab_platform_test_override_bearer(
        topo->ctrl_platform,
        &topo->bearer_inject->bearer_ops,
        &topo->bearer_inject->tx_gate_ops);
    ninlil_posix_lab_platform_test_override_bearer(
        topo->end_platform,
        &topo->bearer_inject->bearer_ops,
        &topo->bearer_inject->tx_gate_ops);

    set_id(&topo->ctrl_runtime_id, 0x10u);
    set_id(&topo->end_runtime_id, 0x21u);
    SCENARIO_REQUIRE(align_scenario_clocks(topo));
    ninlil_c5_lab_radio_stats_snapshot(topo->end_radio, &stats_before);
    ninlil_c5_lab_radio_stats_snapshot(topo->ctrl_radio, &ctrl_stats_before);

    ctrl_cfg = runtime_config(NINLIL_ROLE_CONTROLLER, CTRL_NS, sizeof(CTRL_NS) - 1u, 0x10u);
    end_cfg = runtime_config(NINLIL_ROLE_ENDPOINT, END_NS, sizeof(END_NS) - 1u, 0x21u);
    SCENARIO_REQUIRE(ninlil_model_runtime_validate_and_derive(
                &ctrl_cfg, ninlil_posix_lab_platform_ops(topo->ctrl_platform), &validation)
        == NINLIL_OK);
    SCENARIO_REQUIRE(ninlil_runtime_create(
                &ctrl_cfg, ninlil_posix_lab_platform_ops(topo->ctrl_platform), &ctrl_rt)
        == NINLIL_OK);
    SCENARIO_REQUIRE(ninlil_model_runtime_validate_and_derive(
                &end_cfg, ninlil_posix_lab_platform_ops(topo->end_platform), &validation)
        == NINLIL_OK);
    SCENARIO_REQUIRE(ninlil_runtime_create(
                &end_cfg, ninlil_posix_lab_platform_ops(topo->end_platform), &end_rt)
        == NINLIL_OK);
    SCENARIO_REQUIRE(ninlil_test_bearer_set_path_up(topo->shared_bearer, &topo->ctrl_runtime_id, 1));
    SCENARIO_REQUIRE(ninlil_test_bearer_set_path_up(topo->shared_bearer, &topo->end_runtime_id, 1));

    descriptor = desired_descriptor(0x70u);
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    SCENARIO_REQUIRE(ninlil_service_register(ctrl_rt, &descriptor, &callbacks, &ctrl_svc) == NINLIL_OK);
    descriptor = desired_descriptor(0x81u);
    callbacks.on_delivery = endpoint_delivery_cb;
    callbacks.on_reconcile = endpoint_reconcile_cb;
    SCENARIO_REQUIRE(ninlil_service_register(end_rt, &descriptor, &callbacks, &end_svc) == NINLIL_OK);

    (void)memset(payload, 0x42, sizeof(payload));
    (void)memset(&submission, 0, sizeof(submission));
    set_header(&submission.abi_version, &submission.struct_size, sizeof(submission));
    submission.schema_major = 1u;
    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    set_id(&target.target_runtime_id, 0x21u);
    set_id(&target.target_application_instance_id, 0x81u);
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_APPLIED;
    submission.effect_deadline_ms = 5000u;
    submission.evidence_grace_ms = 1000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idem_key;
    submission.idempotency_key.length = sizeof(idem_key) - 1u;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
    set_digest(&submission.content_digest, 0x55u);
    SCENARIO_REQUIRE(ninlil_submit(ctrl_svc, &submission, &submit_result) == NINLIL_OK);
    SCENARIO_REQUIRE(submit_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    for (step = 0u; step < IG_MAX_STEPS; ++step) {
        if (scenario == V1_LAB_IG_SCENARIO_CTRL_RESTART && step == 6u && ctrl_restarted == 0) {
            (void)ninlil_runtime_destroy(ctrl_rt);
            ctrl_rt = NULL;
            SCENARIO_REQUIRE(ninlil_posix_lab_platform_restart(topo->ctrl_platform) == 1);
            SCENARIO_REQUIRE(ninlil_runtime_create(
                        &ctrl_cfg, ninlil_posix_lab_platform_ops(topo->ctrl_platform), &ctrl_rt)
                == NINLIL_OK);
            descriptor = desired_descriptor(0x70u);
            (void)memset(&callbacks, 0, sizeof(callbacks));
            set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
            SCENARIO_REQUIRE(ninlil_service_register(ctrl_rt, &descriptor, &callbacks, &ctrl_svc)
                == NINLIL_OK);
            ctrl_restarted = 1;
        }
        if (scenario == V1_LAB_IG_SCENARIO_END_RESTART && step == 6u && end_restarted == 0) {
            (void)ninlil_runtime_destroy(end_rt);
            end_rt = NULL;
            SCENARIO_REQUIRE(ninlil_posix_lab_platform_restart(topo->end_platform) == 1);
            SCENARIO_REQUIRE(ninlil_runtime_create(
                        &end_cfg, ninlil_posix_lab_platform_ops(topo->end_platform), &end_rt)
                == NINLIL_OK);
            descriptor = desired_descriptor(0x81u);
            (void)memset(&callbacks, 0, sizeof(callbacks));
            set_header(&callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
            callbacks.on_delivery = endpoint_delivery_cb;
            callbacks.on_reconcile = endpoint_reconcile_cb;
            SCENARIO_REQUIRE(ninlil_service_register(end_rt, &descriptor, &callbacks, &end_svc)
                == NINLIL_OK);
            end_restarted = 1;
        }
        if (scenario == V1_LAB_IG_SCENARIO_STORAGE_FAULT && topo->storage_fault_armed != 0u
            && step == 4u) {
            SCENARIO_REQUIRE(corrupt_db(ctrl_db));
            topo->storage_fault_armed = 0u;
        }
        if (scenario == V1_LAB_IG_SCENARIO_TIMEOUT && step > 4u) {
            SCENARIO_REQUIRE(advance_all_clocks(topo, 6000u));
        } else if (scenario == V1_LAB_IG_SCENARIO_ACK_LOSS
            || scenario == V1_LAB_IG_SCENARIO_DATA_DUPLICATE) {
            if (step > 2u) {
                SCENARIO_REQUIRE(advance_all_clocks(topo, 400u));
            }
        } else if (scenario == V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED && step > 1u) {
            SCENARIO_REQUIRE(advance_all_clocks(topo, 400u));
        } else if (scenario == V1_LAB_IG_SCENARIO_REORDER_REPLAY && step > 2u) {
            SCENARIO_REQUIRE(advance_all_clocks(topo, 400u));
        }
        if (scenario == V1_LAB_IG_SCENARIO_REORDER_REPLAY
            && topo->replay_frame_len > 0u
            && topo->replay_injected == 0u
            && step == 8u) {
            (void)ninlil_c5_lab_radio_channel_deliver(
                &topo->channel_fwd, topo->replay_frame, topo->replay_frame_len);
            topo->replay_injected += 1u;
        }
        (void)memset(&budget, 0, sizeof(budget));
        set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
        budget.max_ingress_messages = 8u;
        budget.max_callbacks = 8u;
        budget.max_state_transitions = 16u;
        budget.max_bearer_sends = 8u;
        (void)memset(&step_result, 0, sizeof(step_result));
        (void)ninlil_runtime_step(end_rt, &budget, &step_result);
        (void)ninlil_runtime_step(ctrl_rt, &budget, &step_result);
        pump_usb(topo);

        if (scenario == V1_LAB_IG_SCENARIO_HAPPY && topo->bearer_inject->recv_count >= 1u
            && g_delivery_calls >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if ((scenario == V1_LAB_IG_SCENARIO_ACK_LOSS
                || scenario == V1_LAB_IG_SCENARIO_DATA_DUPLICATE
                || scenario == V1_LAB_IG_SCENARIO_CTRL_RESTART
                || scenario == V1_LAB_IG_SCENARIO_END_RESTART)
            && topo->bearer_inject->recv_count >= 1u && g_delivery_calls >= 1u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == V1_LAB_IG_SCENARIO_REORDER_REPLAY
            && g_delivery_calls >= 1u
            && topo->replay_injected > 0u) {
            g_outcome_satisfied = 1u;
            break;
        }
        if (scenario == V1_LAB_IG_SCENARIO_REORDER_REPLAY && step > 120u) {
            break;
        }
        if (scenario == V1_LAB_IG_SCENARIO_TIMEOUT && step > 20u) {
            break;
        }
        if ((scenario == V1_LAB_IG_SCENARIO_RETRY_EXHAUSTED
                || scenario == V1_LAB_IG_SCENARIO_CRC_FAULT
                || scenario == V1_LAB_IG_SCENARIO_AUTH_FAULT
                || scenario == V1_LAB_IG_SCENARIO_STORAGE_FAULT)
            && step > 40u) {
            break;
        }
    }

    ninlil_c5_lab_radio_stats_snapshot(topo->end_radio, &stats_after);
    ninlil_c5_lab_radio_stats_snapshot(topo->ctrl_radio, &ctrl_stats_after);
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->scenario_id = scenario;
    out_result->delivery_calls = g_delivery_calls;
    out_result->outcome_satisfied = g_outcome_satisfied;
    out_result->spi_tx_count = (uint32_t)(
        (stats_after.spi_tx_count - stats_before.spi_tx_count)
        + (ctrl_stats_after.spi_tx_count - ctrl_stats_before.spi_tx_count));
    out_result->bounded_termination = step < IG_MAX_STEPS ? 1u : 0u;
    out_result->rx_auth_fail =
        (uint32_t)(stats_after.rx_auth_fail - stats_before.rx_auth_fail);
    out_result->rx_replay = (uint32_t)(stats_after.rx_replay - stats_before.rx_replay);

    if (scenario == V1_LAB_IG_SCENARIO_HAPPY
        || scenario == V1_LAB_IG_SCENARIO_ACK_LOSS
        || scenario == V1_LAB_IG_SCENARIO_DATA_DUPLICATE
        || scenario == V1_LAB_IG_SCENARIO_CTRL_RESTART
        || scenario == V1_LAB_IG_SCENARIO_END_RESTART) {
        out_result->false_success = (g_outcome_satisfied == 0u || g_delivery_calls == 0u) ? 1u : 0u;
        out_result->fail_closed = 0u;
    } else if (scenario == V1_LAB_IG_SCENARIO_REORDER_REPLAY) {
        out_result->false_success = (g_delivery_calls > 1u) ? 1u : 0u;
        out_result->fail_closed = 0u;
    } else {
        out_result->false_success = g_outcome_satisfied;
        out_result->fail_closed = (g_outcome_satisfied == 0u) ? 1u : 0u;
    }

    if (ctrl_rt != NULL) {
        (void)ninlil_runtime_destroy(ctrl_rt);
    }
    if (end_rt != NULL) {
        (void)ninlil_runtime_destroy(end_rt);
    }
    if (topo->ctrl_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->ctrl_platform);
        topo->ctrl_platform = NULL;
    }
    if (topo->end_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->end_platform);
        topo->end_platform = NULL;
    }
    (void)unlink(ctrl_db);
    (void)unlink(end_db);
    return 1;

scenario_fail:
    if (ctrl_rt != NULL) {
        (void)ninlil_runtime_destroy(ctrl_rt);
    }
    if (end_rt != NULL) {
        (void)ninlil_runtime_destroy(end_rt);
    }
    if (topo->ctrl_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->ctrl_platform);
        topo->ctrl_platform = NULL;
    }
    if (topo->end_platform != NULL) {
        ninlil_posix_lab_platform_destroy(topo->end_platform);
        topo->end_platform = NULL;
    }
    (void)unlink(ctrl_db);
    (void)unlink(end_db);
    return 0;
}

int v1_lab_integration_topology_init(
    v1_lab_integration_topology_t **out_topology,
    const char *workdir)
{
    v1_lab_integration_topology_t *topo;
    ninlil_test_bearer_config_t bearer_config;
    ninlil_c4_lab_usb_config_t usb_cfg;
    cookie_rng_ctx_t cookie_rng = {0xA9u};

    if (out_topology == NULL || workdir == NULL) {
        return 0;
    }
    topo = (v1_lab_integration_topology_t *)calloc(1u, sizeof(*topo));
    if (topo == NULL) {
        return 0;
    }
    (void)snprintf(topo->workdir, sizeof(topo->workdir), "%s", workdir);
    REQUIRE(ninlil_r7_crypto_openssl3_provider_init(&topo->crypto) == NINLIL_R7_CRYPTO_OK);
    m4_lab_fixture_seed_membership(&topo->reg);
    m4_lab_fixture_site_config(&topo->m4_config);
    ninlil_c3_lab_context_store_init(&topo->tx_store, &topo->crypto);
    ninlil_c3_lab_context_store_init(&topo->rx_store, &topo->crypto);
    REQUIRE(install_contexts(topo));
    REQUIRE(setup_r5_c6(topo));
    ninlil_c5_lab_radio_channel_init(&topo->channel_fwd);
    ninlil_c5_lab_radio_channel_init(&topo->channel_rev);
    REQUIRE(ninlil_c5_lab_radio_init_object(
                &topo->ctrl_radio_obj, &topo->tx_store, topo->c6, &topo->channel_rev, &topo->ctrl_radio)
        == NINLIL_C5_LAB_RADIO_OK);
    REQUIRE(ninlil_c5_lab_radio_init_object(
                &topo->end_radio_obj, &topo->rx_store, topo->c6, &topo->channel_fwd, &topo->end_radio)
        == NINLIL_C5_LAB_RADIO_OK);
    ninlil_fake_byte_stream_init(&topo->ctrl_fake);
    ninlil_fake_byte_stream_init(&topo->cell_fake);
    ninlil_fake_byte_stream_open_up(&topo->ctrl_fake, 1u);
    ninlil_fake_byte_stream_open_up(&topo->cell_fake, 2u);
    (void)memset(&usb_cfg, 0, sizeof(usb_cfg));
    usb_cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CONTROLLER;
    REQUIRE(ninlil_c4_lab_usb_init_object(&topo->ctrl_usb_obj, &usb_cfg, &topo->ctrl_usb)
        == NINLIL_C4_LAB_USB_OK);
    usb_cfg.role = NINLIL_LOGICAL_SESSION_ROLE_CELL;
    usb_cfg.cookie_rng = cookie_rng_cb;
    usb_cfg.cookie_rng_ctx = &cookie_rng;
    REQUIRE(ninlil_c4_lab_usb_init_object(&topo->cell_usb_obj, &usb_cfg, &topo->cell_usb)
        == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind(topo->ctrl_usb, &topo->ctrl_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind(topo->cell_usb, &topo->cell_fake.view) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(ninlil_c4_lab_usb_bind_peer(topo->ctrl_usb, topo->cell_usb) == NINLIL_C4_LAB_USB_OK);
    REQUIRE(bring_up_usb(topo));
    (void)memset(&bearer_config, 0, sizeof(bearer_config));
    bearer_config.max_entries_per_direction = 64u;
    bearer_config.max_bytes_per_direction = 131072u;
    bearer_config.max_permits = 128u;
    bearer_config.permit_issuer_id.bytes[0] = 0x80u;
    bearer_config.permit_issuer_id.bytes[15] = 0x01u;
    bearer_config.initial_clock_epoch_id.bytes[0] = 0xa0u;
    bearer_config.initial_clock_epoch_id.bytes[15] = 0x01u;
    bearer_config.initial_time_ms = 1000u;
    topo->shared_bearer = ninlil_test_bearer_create(&bearer_config);
    REQUIRE(topo->shared_bearer != NULL);
    ninlil_test_bearer_set_defer_peer_enqueue(topo->shared_bearer, 1);
    topo->bearer_inject = bearer_inject_create(topo, topo->shared_bearer);
    REQUIRE(topo->bearer_inject != NULL);
    topo->next_clock_ms = 1000u;
    topo->bearer_clock_ms = 1000u;
    *out_topology = topo;
    return 1;
}

void v1_lab_integration_topology_destroy(v1_lab_integration_topology_t *topology)
{
    if (topology == NULL) {
        return;
    }
    if (topology->bearer_inject != NULL) {
        free(topology->bearer_inject);
    }
    if (topology->shared_bearer != NULL) {
        ninlil_test_bearer_destroy(topology->shared_bearer);
    }
    if (topology->pcp_storage != NULL) {
        ninlil_test_storage_destroy(topology->pcp_storage);
    }
    if (topology->pcp_clock != NULL) {
        ninlil_test_clock_destroy(topology->pcp_clock);
    }
    if (topology->pcp_entropy != NULL) {
        ninlil_test_entropy_destroy(topology->pcp_entropy);
    }
    free(topology);
}

int v1_lab_integration_run_scenario(
    v1_lab_integration_topology_t *topology,
    uint32_t scenario_id,
    v1_lab_integration_scenario_result_t *out_result)
{
    if (topology == NULL || out_result == NULL) {
        return 0;
    }
    return run_single_scenario(topology, scenario_id, out_result);
}

int v1_lab_integration_structural_check(
    v1_lab_integration_topology_t *topology,
    v1_lab_integration_structural_report_t *out_report)
{
    static const char *INTEGRATION_SOURCES[] = {
        "tests/runtime/v1_integration_gate_e2e_test.c",
        "tests/support/v1_lab_integration_topology.c",
    };
    static const char *BYPASS_SYMBOL = "ninlil_c6_lab_spi_tx_bypass_direct";
    static const char *BYPASS_ALLOWLIST[] = {
        "src/radio/c6_lab_spi_tx_sim.c",
        "src/radio/c6_lab_spi_tx_sim.h",
    };
    char repo_root[1024];
    char path[1200];
    char call_pattern[128];
    size_t i;
    uint64_t integration_calls = 0u;
    const char *support = __FILE__;
    const char *slash = strrchr(support, '/');

    if (topology == NULL || out_report == NULL) {
        return 0;
    }
    (void)topology;
    (void)memset(out_report, 0, sizeof(*out_report));
    if (slash == NULL) {
        return 0;
    }
    {
        size_t prefix = (size_t)(slash - support);
        if (prefix + 8u >= sizeof(repo_root)) {
            return 0;
        }
        (void)memcpy(repo_root, support, prefix);
        repo_root[prefix] = '\0';
        if (snprintf(repo_root + prefix, sizeof(repo_root) - prefix, "/../..")
            <= 0) {
            return 0;
        }
    }
    if (snprintf(
            call_pattern,
            sizeof(call_pattern),
            "%s(",
            BYPASS_SYMBOL)
        <= 0) {
        return 0;
    }
    for (i = 0u; i < sizeof(INTEGRATION_SOURCES) / sizeof(INTEGRATION_SOURCES[0]); ++i) {
        FILE *fp;
        char line[512];
        if (snprintf(path, sizeof(path), "%s/%s", repo_root, INTEGRATION_SOURCES[i])
            <= 0) {
            return 0;
        }
        fp = fopen(path, "r");
        if (fp == NULL) {
            return 0;
        }
        while (fgets(line, (int)sizeof(line), fp) != NULL) {
            if (strstr(line, call_pattern) != NULL) {
                integration_calls += 1u;
            }
        }
        (void)fclose(fp);
    }
    if (integration_calls != 0u) {
        return 0;
    }
    for (i = 0u; i < sizeof(BYPASS_ALLOWLIST) / sizeof(BYPASS_ALLOWLIST[0]); ++i) {
        FILE *fp;
        char line[512];
        int found = 0;
        if (snprintf(path, sizeof(path), "%s/%s", repo_root, BYPASS_ALLOWLIST[i]) <= 0) {
            return 0;
        }
        fp = fopen(path, "r");
        if (fp == NULL) {
            return 0;
        }
        while (fgets(line, (int)sizeof(line), fp) != NULL) {
            if (strstr(line, BYPASS_SYMBOL) != NULL) {
                found = 1;
                break;
            }
        }
        (void)fclose(fp);
        if (found == 0) {
            return 0;
        }
    }
    out_report->bypass_call_sites = integration_calls;
    out_report->bypass_attempt_count = 0u;
    out_report->production_bypass_on_success = 0u;
    return 1;
}
