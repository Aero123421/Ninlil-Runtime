/*
 * Combined owner/cell + durable-storage self-test source.
 * Real ISR: esp_timer ESP_TIMER_ISR (requires SUPPORTS_ISR_DISPATCH_METHOD).
 * Storage: flash bind + FULL → COMMIT_UNKNOWN (ESP_UNPROVEN).
 * Compile/link ≠ HIL PASS / dual-core race PASS / physical power-cut HIL.
 * Device: idf.py flash monitor.
 */

#include "ninlil/platform.h"
#include "ninlil/version.h"

#include "ninlil_esp_idf/cell_agent_storage.h"
#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/execution.h"
#include "ninlil_esp_idf/loopback_tx_permit.h"
#include "ninlil_esp_idf/owner_task_storage.h"
#include "ninlil_esp_idf/usb_cdc.h"
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"

/* R7 production-private link probe; not a public component include. */
#include "r7_crypto_mbedtls.h"
#include "r7_context_binding.h"
#include "r7_wire_codec.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <string.h>

static const char *TAG = "ninlil_m3_owner_qa";

static ninlil_esp_idf_clock_t s_clock;
static ninlil_esp_idf_entropy_t s_entropy;
static ninlil_esp_idf_execution_t s_execution;
static ninlil_esp_idf_loopback_tx_permit_t s_loopback;
static ninlil_esp_idf_cell_agent_t s_agent;

/*
 * Standalone owner forward-extension fixture for smoke.
 * Must NOT live on app_main stack: owner_task_t embeds FreeRTOS stack+TCB
 * (~4KiB+), which alone exceeds CONFIG_ESP_MAIN_TASK_STACK_SIZE (3584 on
 * official v5.5.3). BSS placement uses the type's natural alignment
 * (StackType_t / StaticTask_t). Zero before init only — after shutdown the
 * retired owner state is retained as lifecycle evidence (no full memset).
 */
typedef struct {
    ninlil_esp_idf_owner_task_config_t known;
    uint8_t tail[16];
} smoke_ext_owner_cfg_t;

static ninlil_esp_idf_owner_task_t s_standalone_owner;
static smoke_ext_owner_cfg_t s_ext_owner_cfg;

static EventGroupHandle_t s_ev;
#define EV_PROD_DONE BIT0

static ninlil_esp_idf_owner_task_t *s_isr_owner;
static esp_timer_handle_t s_isr_timer;
static portMUX_TYPE s_isr_ctr_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_isr_ok;
static uint32_t s_isr_fail;
static uint32_t s_prod_ok;
static uint32_t s_prod_full;

/*
 * Keep provider storage out of app_main's measured stack frame. The smoke
 * initializes the real private adapter so its archive member and all mbedTLS
 * dependencies must resolve into the final ESP32-S3 ELF.
 */
static ninlil_r7_crypto_provider s_r7_crypto_provider;

static int smoke_r7_crypto_link(void)
{
    ninlil_r7_crypto_status st;

    (void)memset(&s_r7_crypto_provider, 0, sizeof(s_r7_crypto_provider));
    st = ninlil_r7_crypto_mbedtls_provider_init(&s_r7_crypto_provider);
    if (st != NINLIL_R7_CRYPTO_OK
        || s_r7_crypto_provider.abi_version
            != NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION
        || s_r7_crypto_provider.struct_size
            != (uint32_t)sizeof(s_r7_crypto_provider)
        || s_r7_crypto_provider.reserved_zero != 0u
        || s_r7_crypto_provider.sha256 == NULL
        || s_r7_crypto_provider.hkdf_extract_sha256 == NULL
        || s_r7_crypto_provider.hkdf_expand_sha256 == NULL
        || s_r7_crypto_provider.aes128_gcm_seal == NULL
        || s_r7_crypto_provider.aes128_gcm_open == NULL) {
        ESP_LOGE(TAG, "R7 mbedTLS provider init/link failed status=%u",
            (unsigned)st);
        return -1;
    }
    ESP_LOGI(TAG,
        "R7 mbedTLS provider initialized; compile/link evidence only; "
        "device KAT/HIL pending");
    return 0;
}

/*
 * R7 T1b context binding + verified HKDF final-ELF presence probe (docs/33 §10).
 *
 * BSS-backed fixed semantic inputs + committed expected digest/traffic secret
 * from oracle vectors R7-T1B-HOP-FIELD-D0-MIN and R7-T1B-E2E-FIELD-D0-MIN.
 * Byte constants are copied from the committed subset artifact; the test-only
 * generated header is never included in ESP production.
 *
 * Exercises all six production APIs (Hop/E2E encode + digest + verified derive)
 * via the accepted mbedTLS provider. Expected digest is the committed oracle
 * constant — never recomputed from the same untrusted input and fed back as
 * authority (docs/33 §7 / ADR-0013 prohibited pattern).
 *
 * Compile/link evidence only — not device KAT, RF/USB HIL, FIELD, or R7 complete.
 */
/* Hop FIELD D0 MIN committed semantic inputs (exact 16-byte site domain). */
static const uint8_t s_r7_t1b_hop_site16[16] = {
    0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
    0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4
};
static const uint8_t s_r7_t1b_hop_attachment1[1] = { 0xe6 };
static const uint8_t s_r7_t1b_hop_initiator1[1] = { 0xf6 };
static const uint8_t s_r7_t1b_hop_responder1[1] = { 0x07 };
static const uint8_t s_r7_t1b_hop_authority1[1] = { 0x17 };
/* Committed expected digest + traffic secret (oracle; not derived here). */
static const uint8_t s_r7_t1b_hop_expected_digest32[32] = {
    0x18, 0x68, 0x65, 0x3c, 0xb8, 0x5f, 0xce, 0x90,
    0xb6, 0x22, 0x75, 0xd8, 0x2d, 0xac, 0x64, 0xba,
    0xd9, 0x7f, 0x59, 0x40, 0x83, 0x25, 0xab, 0x0a,
    0x4d, 0xf3, 0x41, 0xe7, 0x38, 0x3d, 0x96, 0x7f
};
static const uint8_t s_r7_t1b_hop_traffic_secret32[32] = {
    0x28, 0xd4, 0xbc, 0xd5, 0xf4, 0x99, 0x04, 0xa3,
    0x6c, 0xbe, 0x66, 0x62, 0x30, 0xc2, 0xe6, 0xe3,
    0x19, 0x9e, 0xc5, 0x14, 0x8a, 0x7f, 0xa1, 0xf0,
    0xab, 0x6f, 0x49, 0xf1, 0xce, 0xb5, 0xe4, 0x0e
};
/* First 8 bytes of committed hop DATA key (basic expected-byte check). */
static const uint8_t s_r7_t1b_hop_data_key16_prefix8[8] = {
    0x42, 0xa5, 0xbc, 0xac, 0x23, 0x3b, 0x9b, 0x0d
};

/* E2E FIELD D0 MIN committed semantic inputs. */
static const uint8_t s_r7_t1b_e2e_site16[16] = {
    0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1,
    0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9
};
static const uint8_t s_r7_t1b_e2e_security1[1] = { 0xbb };
static const uint8_t s_r7_t1b_e2e_sender1[1] = { 0xcb };
static const uint8_t s_r7_t1b_e2e_receiver1[1] = { 0xdb };
static const uint8_t s_r7_t1b_e2e_authority1[1] = { 0xeb };
static const uint8_t s_r7_t1b_e2e_expected_digest32[32] = {
    0xa8, 0xb6, 0x6f, 0x1a, 0x4a, 0xbf, 0x1e, 0xaa,
    0x59, 0x83, 0x26, 0x89, 0x02, 0xc2, 0xa7, 0x69,
    0x45, 0xe3, 0xa7, 0x69, 0xd5, 0x59, 0x07, 0x51,
    0x03, 0x08, 0xae, 0xce, 0x0f, 0x00, 0x95, 0x04
};
static const uint8_t s_r7_t1b_e2e_traffic_secret32[32] = {
    0xb4, 0xa6, 0x87, 0x89, 0x6f, 0x6e, 0x31, 0x74,
    0x24, 0x5c, 0x1f, 0xec, 0xe5, 0x8d, 0xef, 0xb5,
    0xfe, 0xdf, 0x5e, 0xec, 0xb6, 0x7b, 0x1b, 0x7a,
    0x32, 0x57, 0x31, 0xa1, 0x3d, 0x96, 0x7f, 0x23
};
/* First 8 bytes of committed e2e key (basic expected-byte check). */
static const uint8_t s_r7_t1b_e2e_key16_prefix8[8] = {
    0x3b, 0x62, 0x54, 0x27, 0xca, 0xb2, 0x77, 0xa9
};

/* Large outputs stay in BSS — not on app_main stack. */
static ninlil_r7_hop_binding_input s_r7_t1b_hop_input;
static ninlil_r7_e2e_binding_input s_r7_t1b_e2e_input;
static uint8_t s_r7_t1b_hop_canon[NINLIL_R7_BINDING_HOP_CANON_MAX];
static uint8_t s_r7_t1b_e2e_canon[NINLIL_R7_BINDING_E2E_CANON_MAX];
static uint8_t s_r7_t1b_hop_digest32[32];
static uint8_t s_r7_t1b_e2e_digest32[32];
static ninlil_r7_hop_key_bundle s_r7_t1b_hop_bundle;
static ninlil_r7_e2e_key_bundle s_r7_t1b_e2e_bundle;

static int smoke_r7_t1b_binding_link(void)
{
    size_t hop_len = 0u;
    size_t e2e_len = 0u;
    int32_t st;

    if (s_r7_crypto_provider.sha256 == NULL
        || s_r7_crypto_provider.hkdf_extract_sha256 == NULL
        || s_r7_crypto_provider.hkdf_expand_sha256 == NULL) {
        ESP_LOGE(TAG,
            "R7 T1b binding link requires prior crypto provider init");
        return -1;
    }

    /* Fixed Hop FIELD D0 MIN semantic input (oracle; immutable constants). */
    (void)memset(&s_r7_t1b_hop_input, 0, sizeof(s_r7_t1b_hop_input));
    s_r7_t1b_hop_input.environment_code = NINLIL_R7_BINDING_ENV_FIELD;
    s_r7_t1b_hop_input.site_domain.bytes = s_r7_t1b_hop_site16;
    s_r7_t1b_hop_input.site_domain.length = 16u;
    s_r7_t1b_hop_input.membership_epoch = 1ull;
    s_r7_t1b_hop_input.attachment_id.bytes = s_r7_t1b_hop_attachment1;
    s_r7_t1b_hop_input.attachment_id.length = 1u;
    s_r7_t1b_hop_input.attachment_epoch = 1ull;
    s_r7_t1b_hop_input.initiator_stable_id.bytes = s_r7_t1b_hop_initiator1;
    s_r7_t1b_hop_input.initiator_stable_id.length = 1u;
    s_r7_t1b_hop_input.responder_stable_id.bytes = s_r7_t1b_hop_responder1;
    s_r7_t1b_hop_input.responder_stable_id.length = 1u;
    s_r7_t1b_hop_input.controller_authority_id.bytes = s_r7_t1b_hop_authority1;
    s_r7_t1b_hop_input.controller_authority_id.length = 1u;
    s_r7_t1b_hop_input.controller_term = 1ull;
    s_r7_t1b_hop_input.hop_context_id = 1u;
    s_r7_t1b_hop_input.direction_code = NINLIL_R7_BINDING_DIR_IR;

    hop_len = 0u;
    (void)memset(s_r7_t1b_hop_canon, 0xA5, sizeof(s_r7_t1b_hop_canon));
    st = ninlil_r7_encode_hop_binding(
        &s_r7_t1b_hop_input,
        s_r7_t1b_hop_canon,
        83u,
        &hop_len);
    if (st != NINLIL_R7_BINDING_OK || hop_len != 83u
        || s_r7_t1b_hop_canon[0] != (uint8_t)'N'
        || s_r7_t1b_hop_canon[20] != NINLIL_R7_BINDING_PROFILE_ID
        || s_r7_t1b_hop_canon[21] != NINLIL_R7_BINDING_ENV_FIELD) {
        ESP_LOGE(TAG,
            "R7 T1b hop encode link failed status=%ld len=%u",
            (long)st, (unsigned)hop_len);
        return -1;
    }

    (void)memset(s_r7_t1b_hop_digest32, 0xA5, sizeof(s_r7_t1b_hop_digest32));
    st = ninlil_r7_digest_hop_binding(
        &s_r7_crypto_provider,
        &s_r7_t1b_hop_input,
        s_r7_t1b_hop_digest32);
    if (st != NINLIL_R7_BINDING_OK
        || memcmp(s_r7_t1b_hop_digest32, s_r7_t1b_hop_expected_digest32, 32)
            != 0) {
        ESP_LOGE(TAG, "R7 T1b hop digest link failed status=%ld", (long)st);
        return -1;
    }

    /*
     * Verified derive uses the committed expected digest constant above —
     * not the just-computed digest buffer — so this path cannot demonstrate
     * the prohibited untrusted-input digest-as-authority pattern.
     */
    (void)memset(&s_r7_t1b_hop_bundle, 0xA5, sizeof(s_r7_t1b_hop_bundle));
    st = ninlil_r7_derive_hop_key_bundle_verified(
        &s_r7_crypto_provider,
        &s_r7_t1b_hop_input,
        s_r7_t1b_hop_expected_digest32,
        s_r7_t1b_hop_traffic_secret32,
        &s_r7_t1b_hop_bundle);
    if (st != NINLIL_R7_BINDING_OK
        || memcmp(s_r7_t1b_hop_bundle.data_key16,
               s_r7_t1b_hop_data_key16_prefix8, 8)
            != 0) {
        ESP_LOGE(TAG,
            "R7 T1b hop verified-derive link failed status=%ld", (long)st);
        return -1;
    }

    /* Fixed E2E FIELD D0 MIN semantic input. */
    (void)memset(&s_r7_t1b_e2e_input, 0, sizeof(s_r7_t1b_e2e_input));
    s_r7_t1b_e2e_input.environment_code = NINLIL_R7_BINDING_ENV_FIELD;
    s_r7_t1b_e2e_input.site_domain.bytes = s_r7_t1b_e2e_site16;
    s_r7_t1b_e2e_input.site_domain.length = 16u;
    s_r7_t1b_e2e_input.membership_epoch = 1ull;
    s_r7_t1b_e2e_input.e2e_security_id.bytes = s_r7_t1b_e2e_security1;
    s_r7_t1b_e2e_input.e2e_security_id.length = 1u;
    s_r7_t1b_e2e_input.e2e_security_epoch = 1ull;
    s_r7_t1b_e2e_input.sender_stable_id.bytes = s_r7_t1b_e2e_sender1;
    s_r7_t1b_e2e_input.sender_stable_id.length = 1u;
    s_r7_t1b_e2e_input.receiver_stable_id.bytes = s_r7_t1b_e2e_receiver1;
    s_r7_t1b_e2e_input.receiver_stable_id.length = 1u;
    s_r7_t1b_e2e_input.authority_id.bytes = s_r7_t1b_e2e_authority1;
    s_r7_t1b_e2e_input.authority_id.length = 1u;
    s_r7_t1b_e2e_input.authority_term = 1ull;
    s_r7_t1b_e2e_input.e2e_context_id = 1u;
    s_r7_t1b_e2e_input.direction_code = NINLIL_R7_BINDING_DIR_IR;

    e2e_len = 0u;
    (void)memset(s_r7_t1b_e2e_canon, 0xA5, sizeof(s_r7_t1b_e2e_canon));
    st = ninlil_r7_encode_e2e_binding(
        &s_r7_t1b_e2e_input,
        s_r7_t1b_e2e_canon,
        81u,
        &e2e_len);
    if (st != NINLIL_R7_BINDING_OK || e2e_len != 81u
        || s_r7_t1b_e2e_canon[0] != (uint8_t)'N'
        || s_r7_t1b_e2e_canon[20] != NINLIL_R7_BINDING_PROFILE_ID
        || s_r7_t1b_e2e_canon[21] != NINLIL_R7_BINDING_ENV_FIELD) {
        ESP_LOGE(TAG,
            "R7 T1b e2e encode link failed status=%ld len=%u",
            (long)st, (unsigned)e2e_len);
        return -1;
    }

    (void)memset(s_r7_t1b_e2e_digest32, 0xA5, sizeof(s_r7_t1b_e2e_digest32));
    st = ninlil_r7_digest_e2e_binding(
        &s_r7_crypto_provider,
        &s_r7_t1b_e2e_input,
        s_r7_t1b_e2e_digest32);
    if (st != NINLIL_R7_BINDING_OK
        || memcmp(s_r7_t1b_e2e_digest32, s_r7_t1b_e2e_expected_digest32, 32)
            != 0) {
        ESP_LOGE(TAG, "R7 T1b e2e digest link failed status=%ld", (long)st);
        return -1;
    }

    (void)memset(&s_r7_t1b_e2e_bundle, 0xA5, sizeof(s_r7_t1b_e2e_bundle));
    st = ninlil_r7_derive_e2e_key_bundle_verified(
        &s_r7_crypto_provider,
        &s_r7_t1b_e2e_input,
        s_r7_t1b_e2e_expected_digest32,
        s_r7_t1b_e2e_traffic_secret32,
        &s_r7_t1b_e2e_bundle);
    if (st != NINLIL_R7_BINDING_OK
        || memcmp(s_r7_t1b_e2e_bundle.key16, s_r7_t1b_e2e_key16_prefix8, 8)
            != 0) {
        ESP_LOGE(TAG,
            "R7 T1b e2e verified-derive link failed status=%ld", (long)st);
        return -1;
    }

    ESP_LOGI(TAG,
        "R7 T1b binding Hop/E2E encode+digest+verified-derive link exercised; "
        "compile/link only; device KAT/HIL pending; not R7 complete");
    return 0;
}

/*
 * R7 T1 pure wire codec final-ELF presence probe (docs/32 §9.9).
 * BSS-backed minimal pack/seal/open — not device KAT / RF / HIL.
 */
static ninlil_r7_wire_e2e_single_fields s_r7_wire_e2e_fields;
static ninlil_r7_wire_outer_data_fields s_r7_wire_outer_fields;
static uint8_t s_r7_wire_key16[16];
static uint8_t s_r7_wire_iv12[12];
static uint8_t s_r7_wire_app[1];
static uint8_t s_r7_wire_e2e_blob[31];
static uint8_t s_r7_wire_frame[66];
static uint8_t s_r7_wire_opened[31];

static int smoke_r7_wire_link(void)
{
    size_t e2e_len = 0u;
    size_t frame_len = 0u;
    size_t opened_len = 0u;
    ninlil_r7_wire_status st;
    ninlil_r7_wire_e2e_single_fields e2e_out;
    ninlil_r7_wire_outer_data_fields outer_out;
    uint8_t aad14[NINLIL_R7_WIRE_E2E_AAD_LEN];
    uint8_t aad19[NINLIL_R7_WIRE_OUTER_AAD_LEN];

    if (s_r7_crypto_provider.aes128_gcm_seal == NULL) {
        ESP_LOGE(TAG, "R7 T1 wire link requires prior crypto provider init");
        return -1;
    }

    (void)memset(&s_r7_wire_e2e_fields, 0, sizeof(s_r7_wire_e2e_fields));
    s_r7_wire_e2e_fields.e2e_context_id = 1u;
    s_r7_wire_e2e_fields.e2e_counter = 1u;
    (void)memset(aad14, 0xA5, sizeof(aad14));
    st = ninlil_r7_wire_pack_e2e_single_aad(
        &s_r7_wire_e2e_fields, aad14, NINLIL_R7_WIRE_E2E_AAD_LEN);
    if (st != NINLIL_R7_WIRE_OK || aad14[0] != NINLIL_R7_WIRE_PROFILE_ID) {
        ESP_LOGE(TAG, "R7 T1 wire pack_e2e link failed status=%ld", (long)st);
        return -1;
    }
    (void)memset(&e2e_out, 0xA5, sizeof(e2e_out));
    st = ninlil_r7_wire_parse_e2e_single_aad(
        aad14, NINLIL_R7_WIRE_E2E_AAD_LEN, &e2e_out);
    if (st != NINLIL_R7_WIRE_OK || e2e_out.e2e_context_id != 1u) {
        ESP_LOGE(TAG, "R7 T1 wire parse_e2e link failed status=%ld", (long)st);
        return -1;
    }

    (void)memset(&s_r7_wire_outer_fields, 0, sizeof(s_r7_wire_outer_fields));
    s_r7_wire_outer_fields.ack_requested = 0u;
    s_r7_wire_outer_fields.hop_remaining = 0u;
    s_r7_wire_outer_fields.hop_context_id = 1u;
    s_r7_wire_outer_fields.hop_counter = 1u;
    (void)memset(aad19, 0xA5, sizeof(aad19));
    st = ninlil_r7_wire_pack_outer_data_aad(
        &s_r7_wire_outer_fields, aad19, NINLIL_R7_WIRE_OUTER_AAD_LEN);
    if (st != NINLIL_R7_WIRE_OK || aad19[0] != NINLIL_R7_WIRE_PROFILE_ID) {
        ESP_LOGE(TAG, "R7 T1 wire pack_outer link failed status=%ld", (long)st);
        return -1;
    }
    (void)memset(&outer_out, 0xA5, sizeof(outer_out));
    st = ninlil_r7_wire_parse_outer_data_aad(
        aad19, NINLIL_R7_WIRE_OUTER_AAD_LEN, &outer_out);
    if (st != NINLIL_R7_WIRE_OK || outer_out.hop_context_id != 1u) {
        ESP_LOGE(TAG, "R7 T1 wire parse_outer link failed status=%ld", (long)st);
        return -1;
    }

    (void)memset(s_r7_wire_key16, 0x11, sizeof(s_r7_wire_key16));
    (void)memset(s_r7_wire_iv12, 0x22, sizeof(s_r7_wire_iv12));
    s_r7_wire_app[0] = 0x41u;
    st = ninlil_r7_wire_seal_e2e_single(
        &s_r7_crypto_provider,
        s_r7_wire_key16,
        s_r7_wire_iv12,
        &s_r7_wire_e2e_fields,
        s_r7_wire_app,
        1u,
        s_r7_wire_e2e_blob,
        sizeof(s_r7_wire_e2e_blob),
        &e2e_len);
    if (st != NINLIL_R7_WIRE_OK || e2e_len != sizeof(s_r7_wire_e2e_blob)) {
        ESP_LOGE(TAG, "R7 T1 wire seal_e2e link failed status=%ld", (long)st);
        return -1;
    }

    st = ninlil_r7_wire_seal_outer_single(
        &s_r7_crypto_provider,
        s_r7_wire_key16,
        s_r7_wire_iv12,
        &s_r7_wire_outer_fields,
        s_r7_wire_e2e_blob,
        e2e_len,
        s_r7_wire_frame,
        sizeof(s_r7_wire_frame),
        &frame_len);
    if (st != NINLIL_R7_WIRE_OK || frame_len != sizeof(s_r7_wire_frame)) {
        ESP_LOGE(TAG, "R7 T1 wire seal_outer link failed status=%ld", (long)st);
        return -1;
    }

    st = ninlil_r7_wire_open_outer_single(
        &s_r7_crypto_provider,
        s_r7_wire_key16,
        s_r7_wire_iv12,
        s_r7_wire_frame,
        frame_len,
        &outer_out,
        s_r7_wire_opened,
        e2e_len,
        &opened_len);
    if (st != NINLIL_R7_WIRE_OK || opened_len != e2e_len) {
        ESP_LOGE(TAG, "R7 T1 wire open_outer link failed status=%ld", (long)st);
        return -1;
    }
    st = ninlil_r7_wire_open_e2e_single(
        &s_r7_crypto_provider,
        s_r7_wire_key16,
        s_r7_wire_iv12,
        s_r7_wire_opened,
        opened_len,
        &e2e_out,
        s_r7_wire_app,
        1u,
        &opened_len);
    if (st != NINLIL_R7_WIRE_OK || opened_len != 1u || s_r7_wire_app[0] != 0x41u) {
        ESP_LOGE(TAG, "R7 T1 wire open_e2e link failed status=%ld", (long)st);
        return -1;
    }

    ESP_LOGI(TAG,
        "R7 T1 wire codec dual-envelope link exercised; compile/link only; "
        "device KAT/HIL pending");
    return 0;
}


/*
 * U2 A2 compile/link smoke: real non-destructive public port symbols.
 * init_object + CLOSED snapshot links the adapter (ops open/close/read/...).
 * Does NOT install USB / open host path here (Required HIL remains pending).
 * Control CDC never receives ESP_LOG (this path uses UART TAG).
 */
static ninlil_esp_idf_usb_cdc_object_t s_usb_cdc_obj;
static ninlil_byte_stream_t s_usb_stream;

static int smoke_usb_cdc_init_closed(void)
{
    ninlil_byte_stream_status_t st;
    ninlil_byte_stream_link_t link;
    uint64_t gen;

    (void)memset(&s_usb_cdc_obj, 0, sizeof(s_usb_cdc_obj));
    (void)memset(&s_usb_stream, 0, sizeof(s_usb_stream));
    st = ninlil_esp_idf_usb_cdc_init_object(&s_usb_cdc_obj, &s_usb_stream);
    if (st != NINLIL_BYTE_STREAM_OK || s_usb_stream.ops == NULL
        || s_usb_stream.ops->open == NULL || s_usb_stream.ops->close == NULL
        || s_usb_stream.ops->read == NULL || s_usb_stream.ops->write == NULL
        || s_usb_stream.ops->poll == NULL || s_usb_stream.ops->link == NULL) {
        ESP_LOGE(TAG, "usb cdc init failed status=%u", (unsigned)st);
        return -1;
    }
    link = s_usb_stream.ops->link(&s_usb_stream);
    gen = s_usb_stream.ops->link_generation(&s_usb_stream);
    if (link != NINLIL_BYTE_STREAM_LINK_CLOSED || gen != 0u) {
        ESP_LOGE(TAG, "usb cdc initial state must be CLOSED gen=0");
        return -1;
    }
    /* Touch object_size/align so they stay linked. */
    if (ninlil_esp_idf_usb_cdc_object_size() < 4096u
        || ninlil_esp_idf_usb_cdc_object_align() == 0u) {
        ESP_LOGE(TAG, "usb cdc object size/align unexpected");
        return -1;
    }
    ESP_LOGI(TAG,
        "usb cdc init CLOSED snapshot linked; compile!=HIL; "
        "Required host CDC roundtrip pending");
    return 0;
}

/* Storage self-test: production bind path; FULL stays ESP_UNPROVEN/COMMIT_UNKNOWN.
 * Large media/workspace is binder-owned (not app_main stack). Keep locals small.
 */
static int smoke_storage_commit_unknown(void)
{
    ninlil_port_esp_storage_flash_binding_t *binding = NULL;
    ninlil_port_esp_storage_config_t config;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ns[] = {'s', 'm', 'k'};
    static const uint8_t key[] = {'k'};
    static const uint8_t value[] = {'v'};
    ninlil_bytes_view_t ns_view = {ns, (uint32_t)sizeof(ns)};
    ninlil_bytes_view_t key_view = {key, (uint32_t)sizeof(key)};
    ninlil_bytes_view_t value_view = {value, (uint32_t)sizeof(value)};
    ninlil_storage_status_t commit_status;
    int result = -1;

    ninlil_port_esp_storage_config_production(&config);
    if (ninlil_port_esp_storage_flash_bind(
            "ninlil_st", &config, &binding, &ops)
        != 0) {
        ESP_LOGE(TAG, "storage flash bind failed");
        goto cleanup;
    }
    if (ops == NULL
        || ops->open(
               ops->user,
               ns_view,
               NINLIL_STORAGE_SCHEMA_M1A,
               &handle)
            != NINLIL_STORAGE_OK
        || ops->begin(
               ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            != NINLIL_STORAGE_OK
        || ops->put(ops->user, txn, key_view, value_view)
            != NINLIL_STORAGE_OK) {
        ESP_LOGE(TAG, "storage open/begin/put failed");
        goto unbind;
    }
    commit_status =
        ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
    txn = NULL;
    if (commit_status != NINLIL_STORAGE_COMMIT_UNKNOWN) {
        ESP_LOGE(TAG,
            "ESP_UNPROVEN FULL must be COMMIT_UNKNOWN, got %u",
            (unsigned)commit_status);
        goto unbind;
    }
    ESP_LOGI(TAG, "storage FULL correctly remains ESP_UNPROVEN");
    result = 0;

unbind:
    if (txn != NULL) {
        (void)ops->rollback(ops->user, txn);
    }
    if (handle != NULL) {
        ops->close(ops->user, handle);
    }
    ninlil_port_esp_storage_flash_unbind(binding);
cleanup:
    return result;
}

static void IRAM_ATTR isr_timer_cb(void *arg)
{
    ninlil_esp_idf_owner_status_t st;
    (void)arg;
    if (s_isr_owner == NULL) {
        return;
    }
    st = ninlil_esp_idf_owner_task_post_tick_from_isr(s_isr_owner);
    portENTER_CRITICAL_ISR(&s_isr_ctr_mux);
    if (st == NINLIL_ESP_IDF_OWNER_OK) {
        s_isr_ok++;
    } else {
        s_isr_fail++;
    }
    portEXIT_CRITICAL_ISR(&s_isr_ctr_mux);
}

static void producer_task(void *arg)
{
    ninlil_esp_idf_owner_task_t *o = (ninlil_esp_idf_owner_task_t *)arg;
    int i;
    ninlil_esp_idf_owner_status_t st;

    for (i = 0; i < 24; ++i) {
        st = ninlil_esp_idf_owner_task_post_tick(o);
        if (st == NINLIL_ESP_IDF_OWNER_OK) {
            s_prod_ok++;
        } else if (st == NINLIL_ESP_IDF_OWNER_MAILBOX_FULL) {
            s_prod_full++;
        }
        vTaskDelay(1);
    }
    (void)xEventGroupSetBits(s_ev, EV_PROD_DONE);
    vTaskDelete(NULL);
}

static void fill_req(ninlil_tx_request_t *r, ninlil_time_sample_t *n)
{
    (void)memset(r, 0, sizeof(*r));
    r->abi_version = NINLIL_ABI_VERSION;
    r->struct_size = (uint16_t)sizeof(*r);
    r->transaction_id.bytes[0] = 1u;
    r->attempt_id.bytes[0] = 2u;
    r->message_kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    r->logical_bytes = 8u;
    r->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memset(n, 0, sizeof(*n));
    n->abi_version = NINLIL_ABI_VERSION;
    n->struct_size = (uint16_t)sizeof(*n);
    n->clock_epoch_id.bytes[0] = 3u;
    n->now_ms = 20u;
    n->trust = NINLIL_CLOCK_TRUSTED;
}

static void smoke_cleanup_basic(void)
{
    ninlil_esp_idf_entropy_shutdown(&s_entropy);
    ninlil_esp_idf_clock_shutdown(&s_clock);
    ninlil_esp_idf_execution_shutdown(&s_execution);
    if (s_ev != NULL) {
        vEventGroupDelete(s_ev);
        s_ev = NULL;
    }
}

void app_main(void)
{
    ninlil_esp_idf_clock_config_t ccfg;
    ninlil_esp_idf_entropy_config_t ecfg;
    ninlil_esp_idf_loopback_tx_permit_config_t lcfg;
    ninlil_esp_idf_cell_agent_config_t acfg;
    ninlil_esp_idf_cell_assignment_t asg;
    ninlil_esp_idf_owner_snapshot_t snap;
    ninlil_esp_idf_tx_gate_lease_t lease_a;
    ninlil_esp_idf_tx_gate_lease_t lease_b;
    ninlil_tx_request_t req;
    ninlil_time_sample_t now;
    ninlil_tx_permit_t permit;
    const ninlil_tx_gate_ops_t *tx;
    ninlil_esp_idf_owner_status_t st;
    esp_timer_create_args_t targs;
    TaskHandle_t prod = NULL;
    EventBits_t bits;
    int fail = 0;
    int i;
    int j;

    s_ev = xEventGroupCreate();
    if (s_ev == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=event_group_null");
        return;
    }
    ESP_LOGI(TAG, "sizeof(owner)=%u stack_bytes=%u max_leases=%u",
        (unsigned)sizeof(ninlil_esp_idf_owner_task_t),
        (unsigned)NINLIL_ESP_IDF_OWNER_TASK_STACK_BYTES,
        (unsigned)NINLIL_ESP_IDF_OWNER_MAX_TX_GATE_LEASES);

    (void)memset(&ccfg, 0, sizeof(ccfg));
    ccfg.abi_version = NINLIL_ABI_VERSION;
    ccfg.struct_size = (uint16_t)sizeof(ccfg);
    ccfg.boot_epoch_id.bytes[0] = 0xe5u;
    (void)memset(&ecfg, 0, sizeof(ecfg));
    ecfg.abi_version = NINLIL_ABI_VERSION;
    ecfg.struct_size = (uint16_t)sizeof(ecfg);
    ecfg.policy = NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG;
    if (ninlil_esp_idf_clock_init(&s_clock, &ccfg) != 0
        || ninlil_esp_idf_entropy_init(&s_entropy, &ecfg) != 0
        || ninlil_esp_idf_execution_init(&s_execution) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=basic_adapter_init");
        smoke_cleanup_basic();
        return;
    }

    /* invalid priority must fail init */
    (void)memset(&s_agent, 0, sizeof(s_agent));
    (void)memset(&acfg, 0, sizeof(acfg));
    acfg.abi_version = NINLIL_ABI_VERSION;
    acfg.struct_size = (uint16_t)sizeof(acfg);
    acfg.owner.abi_version = NINLIL_ABI_VERSION;
    acfg.owner.struct_size = (uint16_t)sizeof(acfg.owner);
    acfg.owner.task_priority = 0xffffu;
    if (ninlil_esp_idf_cell_agent_init(&s_agent, &acfg) == 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=invalid_priority_accepted");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        smoke_cleanup_basic();
        return;
    }

    (void)memset(&s_loopback, 0, sizeof(s_loopback));
    (void)memset(&lcfg, 0, sizeof(lcfg));
    lcfg.abi_version = NINLIL_ABI_VERSION;
    lcfg.struct_size = (uint16_t)sizeof(lcfg);
    lcfg.environment = NINLIL_ENV_TEST;
    lcfg.loopback_enabled = 1u;
    if (ninlil_esp_idf_loopback_tx_permit_init(&s_loopback, &lcfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_init");
        smoke_cleanup_basic();
        return;
    }
    tx = ninlil_esp_idf_loopback_tx_permit_ops(&s_loopback);
    if (tx == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_ops_null");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    fill_req(&req, &now);
    req.logical_bytes = 0u;
    if (tx->acquire(tx->user, &req, &now, &permit) != NINLIL_TX_GATE_DENIED) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_zero_bytes_not_denied");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    fill_req(&req, &now);
    if (tx->acquire(tx->user, &req, &now, &permit) != NINLIL_TX_GATE_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_acquire");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) == 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_shutdown_while_live");
        tx->release_unused(tx->user, &permit);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    tx->release_unused(tx->user, &permit);
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_shutdown");
        smoke_cleanup_basic();
        return;
    }
    (void)memset(&s_loopback, 0, sizeof(s_loopback));
    if (ninlil_esp_idf_loopback_tx_permit_init(&s_loopback, &lcfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_reinit");
        smoke_cleanup_basic();
        return;
    }
    tx = ninlil_esp_idf_loopback_tx_permit_ops(&s_loopback);
    if (tx == NULL) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_ops_null_reinit");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    /*
     * Standalone owner_task_init with forward-extended config (declared
     * struct_size > known sizeof). Exercises production owner_config_stage
     * path on target, not a generic helper-only host probe.
     * Storage/fixture are file-scope BSS (not app_main locals) — see
     * s_standalone_owner / s_ext_owner_cfg above.
     */
    (void)memset(&s_standalone_owner, 0, sizeof(s_standalone_owner));
    (void)memset(&s_ext_owner_cfg, 0, sizeof(s_ext_owner_cfg));
    s_ext_owner_cfg.known.abi_version = NINLIL_ABI_VERSION;
    s_ext_owner_cfg.known.struct_size = (uint16_t)sizeof(s_ext_owner_cfg);
    s_ext_owner_cfg.known.task_priority = 5u;
    (void)memset(s_ext_owner_cfg.tail, 0x5Au, sizeof(s_ext_owner_cfg.tail));
    if (ninlil_esp_idf_owner_task_init(
            &s_standalone_owner,
            (const ninlil_esp_idf_owner_task_config_t *)(const void *)
                &s_ext_owner_cfg)
        != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=owner_init_forward_ext");
        /* Keep BSS evidence; do not wipe failed/partial owner state. */
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_shutdown(&s_standalone_owner)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=owner_shutdown_forward_ext");
        /* Retain retired/partial owner for post-mortem; no full memset. */
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    /* Intentionally keep retired s_standalone_owner / s_ext_owner_cfg state. */

    (void)memset(&s_agent, 0, sizeof(s_agent));
    (void)memset(&acfg, 0, sizeof(acfg));
    acfg.abi_version = NINLIL_ABI_VERSION;
    acfg.struct_size = (uint16_t)sizeof(acfg);
    acfg.owner.abi_version = NINLIL_ABI_VERSION;
    acfg.owner.struct_size = (uint16_t)sizeof(acfg.owner);
    acfg.owner.task_priority = 5u;
    acfg.tx_gate = tx;
    if (ninlil_esp_idf_cell_agent_init(&s_agent, &acfg) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=cell_agent_init");
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    /*
     * Target direct backend evidence (not host pure substitute):
     * 2 leases held → get_snapshot borrowers=2; shutdown BUSY;
     * double/forged release leave snapshot unchanged; only after both
     * released is shutdown allowed.
     */
    st = ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(&s_agent, &lease_a);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_a_acquire");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    st = ninlil_esp_idf_cell_agent_acquire_tx_gate_lease(&s_agent, &lease_b);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_b_acquire");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 2u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_borrowers_not_2");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_shutdown(&s_agent)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=shutdown_not_busy_two_leases");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a);
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_a_release");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_a)
        != NINLIL_ESP_IDF_OWNER_LEASE_STALE) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=double_release_not_stale");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    {
        ninlil_esp_idf_tx_gate_lease_t forged = lease_b;
        forged.token ^= 0x11u;
        if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &forged)
            != NINLIL_ESP_IDF_OWNER_LEASE_STALE) {
            ESP_LOGE(TAG, "SELFTEST FAIL reason=forged_release_not_stale");
            (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(
                &s_agent, &lease_b);
            (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
            (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
            smoke_cleanup_basic();
            return;
        }
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 1u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_not_1_after_stale");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=set_while_B_held");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_shutdown(&s_agent)
        != NINLIL_ESP_IDF_OWNER_BUSY) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=shutdown_not_busy_one_lease");
        (void)ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_release_tx_gate_lease(&s_agent, &lease_b)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=lease_b_release");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap)
        != NINLIL_ESP_IDF_OWNER_OK
        || snap.tx_gate_borrowers != 0u) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=snapshot_borrowers_not_0");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }
    if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
        != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=set_after_all_released");
        (void)ninlil_esp_idf_cell_agent_shutdown(&s_agent);
        (void)ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback);
        smoke_cleanup_basic();
        return;
    }

    for (i = 0; i < 3; ++i) {
        st = ninlil_esp_idf_cell_agent_start(&s_agent);
        if (st != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(40));

        s_isr_owner = &s_agent.owner;
        s_isr_ok = 0u;
        s_isr_fail = 0u;
        s_prod_ok = 0u;
        s_prod_full = 0u;
        (void)xEventGroupClearBits(s_ev, EV_PROD_DONE);

        (void)memset(&targs, 0, sizeof(targs));
        targs.callback = isr_timer_cb;
        targs.name = "n_isr";
        targs.dispatch_method = ESP_TIMER_ISR;
        if (esp_timer_create(&targs, &s_isr_timer) != 0) {
            fail = 1;
        } else {
            (void)esp_timer_start_periodic(s_isr_timer, 2000);
        }

        if (xTaskCreatePinnedToCore(
                producer_task, "prod", 3072, &s_agent.owner, 4, &prod, 1)
            != pdPASS) {
            fail = 1;
        }

        (void)memset(&asg, 0, sizeof(asg));
        asg.cell_id = (uint32_t)(i + 1);
        asg.channel_id = 1u;
        asg.role = NINLIL_ROLE_CELL_AGENT_RESERVED;
        asg.assignment_epoch = 1u;
        asg.controller_term = 1u;
        (void)ninlil_esp_idf_cell_agent_apply_assignment(&s_agent, &asg);

        for (j = 0; j < 40; ++j) {
            (void)ninlil_esp_idf_owner_task_post_tick(&s_agent.owner);
        }

        bits = xEventGroupWaitBits(
            s_ev, EV_PROD_DONE, pdTRUE, pdFALSE, pdMS_TO_TICKS(3000));
        if ((bits & EV_PROD_DONE) == 0) {
            fail = 1;
        }

        if (s_isr_timer != NULL) {
            (void)esp_timer_stop(s_isr_timer);
            (void)esp_timer_delete(s_isr_timer);
            s_isr_timer = NULL;
        }
        s_isr_owner = NULL;

        (void)ninlil_esp_idf_owner_task_post_self_stop_probe(&s_agent.owner);
        vTaskDelay(pdMS_TO_TICKS(20));

        st = ninlil_esp_idf_cell_agent_stop(&s_agent);
        if (st != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
            break;
        }
        if (ninlil_esp_idf_cell_agent_stop(&s_agent)
            != NINLIL_ESP_IDF_OWNER_DOUBLE_STOP) {
            fail = 1;
        }
        (void)ninlil_esp_idf_owner_task_get_snapshot(&s_agent.owner, &snap);
        if (snap.lifecycle != NINLIL_ESP_IDF_OWNER_LC_STOPPED) {
            fail = 1;
        }
        ESP_LOGI(TAG,
            "iter %d hwm_bytes=%u isr_ok=%u isr_fail=%u prod_ok=%u full=%u tcb_gen=%u",
            i,
            (unsigned)snap.stack_hwm_bytes,
            (unsigned)s_isr_ok,
            (unsigned)s_isr_fail,
            (unsigned)s_prod_ok,
            (unsigned)s_prod_full,
            (unsigned)snap.tcb_generation);
        if (s_isr_ok == 0u) {
            /* real ISR path should have posted at least once while running */
            fail = 1;
        }
        if (ninlil_esp_idf_owner_task_post_tick(&s_agent.owner)
            == NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
        }
        if (ninlil_esp_idf_cell_agent_set_tx_gate(&s_agent, tx)
            != NINLIL_ESP_IDF_OWNER_OK) {
            fail = 1;
        }
    }

    st = ninlil_esp_idf_cell_agent_shutdown(&s_agent);
    if (st != NINLIL_ESP_IDF_OWNER_OK) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=cell_agent_shutdown");
        fail = 1;
    }
    if (ninlil_esp_idf_loopback_tx_permit_shutdown(&s_loopback) != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL reason=loopback_final_shutdown");
        fail = 1;
    }
    smoke_cleanup_basic();

    /* Owner/cell first, then storage, U2 CDC, and R7 crypto/T1b/wire probes. */
    if (smoke_storage_commit_unknown() != 0) {
        fail = 1;
    }
    if (smoke_usb_cdc_init_closed() != 0) {
        fail = 1;
    }
    if (smoke_r7_crypto_link() != 0) {
        fail = 1;
    }
    /* Binding after provider init, before wire smoke (docs/33 dependency). */
    if (smoke_r7_t1b_binding_link() != 0) {
        fail = 1;
    }
    if (smoke_r7_wire_link() != 0) {
        fail = 1;
    }

    if (fail != 0) {
        ESP_LOGE(TAG, "SELFTEST FAIL (device HIL required for runtime verdict)");
    } else {
        ESP_LOGI(TAG,
            "SELFTEST owner/cell + storage + U2 CDC + R7 crypto/T1b/wire link "
            "exercised; compile!=HIL; U2/R7 Required HIL pending; "
            "not device KAT/RF/FIELD/R7 complete; flash monitor for runtime");
    }
}
