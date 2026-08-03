/*
 * Radio HIL composition: real R2 PCP + R5 profile + R1 HAL + R9 SX1262 phy
 * (Proposed ADR-0025).
 *
 * V1 release HIL path only (no local mock permit, no session RAM ledger):
 *   immutable XIAO ESP32-S3 + Wio-SX1262 board profile
 *     (DIO2 RF-switch, DIO3 TCXO 3.0 V, CAL_ALL)
 *   → approved LAB RF profile docs
 *   → R5 load/activate + site assignment
 *   → PCP flash FULL durable adapter + recover/publish + clock/entropy
 *   → R5 issue → ninlil_radio_hal_transmit_with_permit
 *   → sx1262_r9_edge (SHA-256 + airtime + LBT seal)
 *   → phy_arm_tx (CAD/LBT + sole SetTx)
 *
 * Flash FULL is mandatory: fail closed if flash bind fails.
 * Session RAM ledger is diagnostic-only (NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
 * and is impossible under NINLIL_SX1262_PRODUCTION_BUILD.
 *
 * Recovery honesty:
 *   PCP_RECOVER_SAME_SESSION — in-process recover on live g_pcp (not reboot).
 *   PREPARE_TWO_BOOT / REBOOT / COMPLETE_TWO_BOOT — physical two-boot protocol
 *   (RTC receipt + fresh reconstruct). Never claim restart from same-session.
 *
 * Nonclaims: RF HIL PASS, Japan legal certification, physical power-cut PASS,
 * ADR-0025 Accepted. Physical two-boot / power-cut remain NOT_RUN without
 * device evidence.
 */

#include "sdkconfig.h"

#include "airtime_calculator.h"
#include "domain_store_codec.h"
#include "lab_approved_rf_profiles.h"
#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/sx1262_bus.h"
#include "radio_entropy_drbg.h"
#include "ninlil_port/esp_storage.h"
#include "ninlil_port/esp_storage_flash.h"
#include "ninlil_sx1262_backend.h"
#include "ninlil_sx1262_board_profiles.h"
#include "ninlil_sx1262_phy.h"
#include "pcp_authority.h"
#include "profile_loader.h"
#include "radio_hal.h"
#include "r7_crypto_mbedtls.h"
#include "sx1262_r9_edge.h"

#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
#include "n6_context_store.h"
#include "n6_crypto_provider.h"
#include "ninlil_esp_idf/usb_cdc.h"
#include "r7_frag/r7_r2_authority_clock.h"
#include "v1_lab_board_owner.h"
#include "v1_lab_provisioner.h"
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
#include "ninlil_esp_idf/execution.h"
#include "v1_lab_fabric.h"
#include "v1_lab_peer_runtime.h"
#endif
#endif

/*
 * Session RAM ledger: only when Kconfig diagnostic is ON (default n).
 * Release radio_hil sdkconfig must keep it OFF; evidence gate forbids symbols.
 */
#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
#include "pcp_lab_session_ledger.h"
#include "esp_heap_caps.h"
#endif

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "radio_hil";

/* Board profile defaults match Kconfig. */
#ifndef CONFIG_NINLIL_SX1262_PIN_NSS
#define CONFIG_NINLIL_SX1262_PIN_NSS 41
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_SCK
#define CONFIG_NINLIL_SX1262_PIN_SCK 7
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_MOSI
#define CONFIG_NINLIL_SX1262_PIN_MOSI 9
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_MISO
#define CONFIG_NINLIL_SX1262_PIN_MISO 8
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_RESET
#define CONFIG_NINLIL_SX1262_PIN_RESET 42
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_BUSY
#define CONFIG_NINLIL_SX1262_PIN_BUSY 40
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_DIO1
#define CONFIG_NINLIL_SX1262_PIN_DIO1 39
#endif
#ifndef CONFIG_NINLIL_SX1262_PIN_ANT_SW
#define CONFIG_NINLIL_SX1262_PIN_ANT_SW 38
#endif
#ifndef CONFIG_NINLIL_SX1262_SPI_HOST
#define CONFIG_NINLIL_SX1262_SPI_HOST 1
#endif

/*
 * Fail closed: production / V1 release HIL forbids mock permit minting and
 * session RAM ledger. Session DIAG is a separate non-release profile only.
 */
#if defined(NINLIL_SX1262_PRODUCTION_BUILD) && defined(NINLIL_RADIO_HIL_DIAG_MOCK)
#error "NINLIL_RADIO_HIL_DIAG_MOCK is impossible under NINLIL_SX1262_PRODUCTION_BUILD"
#endif
#if defined(NINLIL_SX1262_PRODUCTION_BUILD) \
    && defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
#error \
    "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG is impossible under NINLIL_SX1262_PRODUCTION_BUILD (V1 release HIL)"
#endif
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD) \
    && !defined(CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH)
#error "V1 board mode requires the V1 LAB radio path"
#endif
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER) \
    && !defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
#error "V1 peer role requires V1 board mode"
#endif

/* Release radio_hil must bind exact XIAO ESP32-S3 + Wio-SX1262 pins. */
#if CONFIG_NINLIL_SX1262_PIN_NSS != NINLIL_SX1262_XIAO_WIO_PIN_NSS
#error "radio_hil pin NSS must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_SCK != NINLIL_SX1262_XIAO_WIO_PIN_SCK
#error "radio_hil pin SCK must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_MOSI != NINLIL_SX1262_XIAO_WIO_PIN_MOSI
#error "radio_hil pin MOSI must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_MISO != NINLIL_SX1262_XIAO_WIO_PIN_MISO
#error "radio_hil pin MISO must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_RESET != NINLIL_SX1262_XIAO_WIO_PIN_RESET
#error "radio_hil pin RESET must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_BUSY != NINLIL_SX1262_XIAO_WIO_PIN_BUSY
#error "radio_hil pin BUSY must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_DIO1 != NINLIL_SX1262_XIAO_WIO_PIN_DIO1
#error "radio_hil pin DIO1 must match XIAO+Wio board profile"
#endif
#if CONFIG_NINLIL_SX1262_PIN_ANT_SW != NINLIL_SX1262_XIAO_WIO_PIN_ANT_SW
#error "radio_hil pin ANT_SW must match XIAO+Wio board profile"
#endif
#if !defined(CONFIG_NINLIL_SX1262_ANT_SW_ACTIVE_HIGH)
#error "radio_hil requires ANT_SW active-high for XIAO+Wio board profile"
#endif

/* ---- BSS: large objects never on app_main stack.
 * Worst retained chain is TX/new-epoch (~18256 B .su sum incl. algorithm_e);
 * CONFIG_ESP_MAIN_TASK_STACK_SIZE ≥ 24576 with gate margin 4096. ---- */
static ninlil_sx1262_backend_object_t g_be_obj = NINLIL_SX1262_OBJECT_INIT;
static ninlil_sx1262_backend_t *g_be;
static ninlil_sx1262_phy_object_t g_phy_obj = NINLIL_SX1262_PHY_OBJECT_INIT;
static ninlil_sx1262_phy_t *g_phy;
static ninlil_esp_idf_sx1262_bus_t g_bus = NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT;
static ninlil_sx1262_rf_profile_t g_prof;
static ninlil_sx1262_r9_edge_object_t g_edge_obj = NINLIL_SX1262_R9_EDGE_OBJECT_INIT;
static ninlil_sx1262_r9_edge_t *g_edge;
static const ninlil_radio_hal_edge_ops_t *g_edge_ops;
static void *g_edge_ctx;
static ninlil_radio_hal_object_t g_hal_obj;
static ninlil_radio_hal_t *g_hal;

static ninlil_pcp_object_t g_pcp_obj = NINLIL_PCP_OBJECT_INIT;
static ninlil_pcp_t *g_pcp;
static ninlil_r5_object_t g_r5_obj = NINLIL_R5_OBJECT_INIT;
static ninlil_r5_t *g_r5;
static const ninlil_storage_ops_t *g_ledger_ops;
static ninlil_port_esp_storage_flash_binding_t *g_flash_binding;
static int g_ledger_is_flash;
#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
static ninlil_pcp_lab_session_ledger_t *g_session_ledger;
#endif
static ninlil_esp_idf_clock_t g_clock;
static ninlil_esp_idf_entropy_t g_entropy;
static ninlil_esp_idf_radio_drbg_t g_radio_drbg;
static uint8_t g_radio_entropy_transition_attempted;
static ninlil_r7_crypto_provider g_r7_crypto;
static ninlil_radio_hal_permit_ops_t g_r5_permit_ops;
static ninlil_radio_hal_digest_ops_t g_digest_ops;
static ninlil_pcp_live_profile_t g_live;

#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
#define NINLIL_RADIO_HIL_V1_N6_SLOTS ((uint32_t)8u)
#define NINLIL_RADIO_HIL_V1_N6_POOL_BYTES ((size_t)4096u)
static ninlil_esp_idf_usb_cdc_object_t g_v1_usb_object;
static ninlil_byte_stream_t g_v1_usb_stream;
static uint8_t g_v1_n6_object[NINLIL_N6_OBJECT_BYTES]
    __attribute__((aligned(NINLIL_N6_OBJECT_ALIGN)));
static uint8_t g_v1_n6_pool[NINLIL_RADIO_HIL_V1_N6_POOL_BYTES];
static ninlil_n6_t *g_v1_n6;
static ninlil_v1_lab_provisioner_t g_v1_provisioner;
static ninlil_v1_lab_board_owner_t g_v1_board_owner;
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
static ninlil_v1_lab_peer_runtime_t g_v1_peer_runtime;
#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
static ninlil_pcp_lab_session_ledger_t *g_v1_peer_ledger;
#endif
static const ninlil_storage_ops_t *g_v1_peer_storage_ops;
static void *g_v1_peer_composition_workspace;
static ninlil_esp_idf_execution_t g_v1_peer_execution;
static ninlil_allocator_ops_t g_v1_peer_allocator;
static ninlil_platform_ops_t g_v1_peer_platform;
static uint32_t g_v1_peer_delivery_count;
#endif
#endif

static int g_inited;
static int g_profile_loaded;
static int g_pcp_recovered;
static int g_pcp_same_session_recover_ok;
static uint8_t g_rx_frame[NINLIL_SX1262_PHY_MAX_FRAME];

/* Per-boot identity (fresh after every reset; never reused across reboots). */
static uint8_t g_boot_id[16];
static uint32_t g_reset_reason;
static uint32_t g_boot_seq;

/* Two-boot recovery receipt (survives esp_restart; not power-cut proof). */
#define NINLIL_RADIO_HIL_TWO_BOOT_MAGIC ((uint32_t)0x32425452u) /* R2B2 LE */
typedef struct ninlil_radio_hil_two_boot_receipt {
    uint32_t magic;
    uint8_t prev_boot_id[16];
    uint32_t pcp_published;
    uint32_t fence;
    uint32_t reset_reason_prepare;
    uint32_t checksum;
} ninlil_radio_hil_two_boot_receipt_t;

RTC_NOINIT_ATTR static ninlil_radio_hil_two_boot_receipt_t g_two_boot_rtc;
static int g_two_boot_prepared;
static int g_two_boot_completed;

static void emit(const char *line)
{
    (void)printf("%s\n", line);
    (void)fflush(stdout);
}

static void hex16(const uint8_t id[16], char out[33])
{
    static const char *hexd = "0123456789abcdef";
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        out[i * 2u] = hexd[(id[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = hexd[id[i] & 0x0fu];
    }
    out[32] = '\0';
}

static int parse_hex16(const char *s, uint8_t out[16])
{
    size_t i;
    if (s == NULL) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        unsigned v = 0u;
        if (s[0] == '\0' || s[1] == '\0') {
            return 0;
        }
        if (sscanf(s, "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
        s += 2;
    }
    return 1;
}

static uint32_t two_boot_checksum(const ninlil_radio_hil_two_boot_receipt_t *r)
{
    uint32_t c = 0xC3C3C3C3u;
    size_t i;
    if (r == NULL) {
        return 0u;
    }
    c ^= r->magic;
    c ^= r->pcp_published;
    c ^= r->fence;
    c ^= r->reset_reason_prepare;
    for (i = 0u; i < 16u; ++i) {
        c = (c * 131u) + (uint32_t)r->prev_boot_id[i];
    }
    return c;
}

static void mint_boot_identity(void)
{
    size_t i;
    uint32_t rnd;
    g_reset_reason = (uint32_t)esp_reset_reason();
    g_boot_seq = 0u;
    do {
        rnd = esp_random();
        for (i = 0u; i < 16u; ++i) {
            g_boot_id[i] =
                (uint8_t)((rnd >> ((i % 4u) * 8u)) ^ (uint8_t)(0x5Au + i));
        }
        /* Mix a second word so all 16 bytes are not low-entropy. */
        rnd = esp_random();
        for (i = 0u; i < 16u; ++i) {
            g_boot_id[i] ^= (uint8_t)((rnd >> ((i % 4u) * 8u)) + (uint8_t)i);
        }
    } while (g_boot_id[0] == 0u && g_boot_id[1] == 0u && g_boot_id[2] == 0u
             && g_boot_id[3] == 0u);
    g_boot_seq = 1u;
    g_two_boot_prepared = 0;
    g_two_boot_completed = 0;
}

static void fill_id(ninlil_radio_hal_id_t *id, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < sizeof(id->bytes); ++i) {
        id->bytes[i] = (uint8_t)(tag + i);
    }
}

static void fill_digest(uint8_t d[32], uint8_t tag)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        d[i] = (uint8_t)(tag + i);
    }
}

static int sha_frame(const uint8_t *f, uint32_t n, uint8_t out[32])
{
    ninlil_model_domain_digest_t d;
    size_t i;

    if (ninlil_model_domain_sha256(f, n, &d) != NINLIL_OK) {
        return 0;
    }
    for (i = 0u; i < 32u; ++i) {
        out[i] = d.bytes[i];
    }
    return 1;
}

static ninlil_radio_hal_status_t hil_digest_verify(
    void *ctx,
    const ninlil_radio_hal_frame_view_t *frame,
    const uint8_t digest[NINLIL_RADIO_HAL_DIGEST_BYTES],
    uint32_t digest_algorithm,
    ninlil_radio_hal_error_t *out_error)
{
    uint8_t computed[32];

    (void)ctx;
    if (digest_algorithm != 1u || frame == NULL || digest == NULL
        || frame->bytes == NULL || frame->length == 0u
        || !sha_frame(frame->bytes, frame->length, computed)
        || ninlil_sx1262_r9_digest_ct_neq(computed, digest) != 0) {
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
            out_error->status = NINLIL_RADIO_HAL_FRAME_MISMATCH;
            out_error->stage = NINLIL_RADIO_HAL_STAGE_DIGEST;
            out_error->reason = NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH;
        }
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_RADIO_HAL_OK;
}

static int fill_board_release_profile(ninlil_sx1262_board_config_t *b)
{
    const ninlil_sx1262_board_config_t *prof;

    if (b == NULL) {
        return -1;
    }
    prof = ninlil_sx1262_board_profile_xiao_wio_sx1262_v1();
    if (prof == NULL
        || ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1(b) != 0) {
        return -1;
    }
    if (!ninlil_sx1262_board_profile_xiao_wio_features_match(b)) {
        return -1;
    }
    if (!ninlil_sx1262_board_profile_xiao_wio_pins_match(
            b->pin_nss,
            b->pin_sck,
            b->pin_mosi,
            b->pin_miso,
            b->pin_reset,
            b->pin_busy,
            b->pin_dio1,
            b->pin_ant_sw)) {
        return -1;
    }
    /* Runtime config must still equal immutable profile (contradiction check). */
    if (!ninlil_sx1262_board_profile_xiao_wio_pins_match(
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_NSS,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_SCK,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_MOSI,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_MISO,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_RESET,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_BUSY,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_DIO1,
            (uint32_t)CONFIG_NINLIL_SX1262_PIN_ANT_SW)) {
        return -1;
    }
    (void)prof;
    return 0;
}

static void make_site_assignment(ninlil_r5_site_assignment_t *a)
{
    (void)memset(a, 0, sizeof(*a));
    fill_id(&a->site_assignment_id, 0x30u);
    a->site_assignment_rev = 4u;
    a->site_assignment_epoch = 9u;
    a->controller_term = 11u;
    fill_digest(a->assignment_digest, 0x50u);
    a->permit_bind_generation = 3u;
    fill_id(&a->transmitter_id, 0x40u);
    a->channel_id = 2u; /* within golden reg 1..3 */
    a->phy.bandwidth_hz = 125000u;
    a->phy.spreading_factor = 7u;
    a->phy.coding_rate_denom = 5u;
    a->phy.preamble_symbols = 8u;
    a->phy.tx_power_mdb = 10000;
    a->phy.phy_flags = 0u;
}

#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
static int session_ledger_init(void)
{
    if (g_session_ledger == NULL) {
        g_session_ledger = (ninlil_pcp_lab_session_ledger_t *)heap_caps_calloc(
            1u,
            sizeof(*g_session_ledger),
            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    if (g_session_ledger == NULL
        || ninlil_pcp_lab_session_ledger_init(
               g_session_ledger, &g_ledger_ops)
            != 0
        || g_ledger_ops == NULL) {
        g_ledger_ops = NULL;
        return 1;
    }
    return 0;
}
#endif

static int radio_entropy_transition(const uint8_t clock_epoch_id[16])
{
    ninlil_pcp_error_t error;
    const ninlil_entropy_ops_t *boot_entropy;
    const ninlil_entropy_ops_t *runtime_entropy;
    uint8_t material[32];
    uint8_t digest[32];
    uint8_t drbg_seeded = 0u;
    int result = 1;

    if (clock_epoch_id == NULL
        || g_radio_entropy_transition_attempted != 0u) {
        return 1;
    }
    g_radio_entropy_transition_attempted = 1u;
    (void)memcpy(material, g_boot_id, 16u);
    (void)memcpy(material + 16u, clock_epoch_id, 16u);
    boot_entropy = ninlil_esp_idf_entropy_ops(&g_entropy);
    if (!sha_frame(material, sizeof(material), digest)
        || boot_entropy == NULL
        || ninlil_esp_idf_radio_drbg_init(
               &g_radio_drbg, boot_entropy, digest)
            != 0) {
        goto retire_boot_entropy;
    }
    drbg_seeded = 1u;

retire_boot_entropy:
    ninlil_esp_idf_entropy_shutdown(&g_entropy);
    if (drbg_seeded == 0u
        || ninlil_esp_idf_entropy_is_ready(&g_entropy) != 0) {
        goto out;
    }
    runtime_entropy = ninlil_esp_idf_radio_drbg_ops(&g_radio_drbg);
    if (runtime_entropy == NULL
        || ninlil_pcp_bind_entropy(g_pcp, runtime_entropy, &error)
            != NINLIL_PCP_OK) {
        goto out;
    }
    result = 0;

out:
    (void)memset(material, 0, sizeof(material));
    (void)memset(digest, 0, sizeof(digest));
    return result;
}

static int authority_init(void)
{
    ninlil_pcp_error_t perr;
    ninlil_r5_error_t rerr;
    const ninlil_entropy_ops_t *authority_entropy;
    ninlil_pcp_instance_seed_t seed;
    ninlil_esp_idf_clock_config_t clock_cfg;
    ninlil_esp_idf_entropy_config_t ent_cfg;
    ninlil_r5_site_assignment_t assign;
    ninlil_r7_crypto_status rst;
    size_t i;
    uint32_t rnd;
    uint8_t reuse_runtime_entropy;

    /* Fail closed without approved profile docs (compile-time embedded). */
    if (sizeof(k_ninlil_lab_approved_hw_v1) != 128u
        || sizeof(k_ninlil_lab_approved_reg_v1) != 160u
        || k_ninlil_lab_approved_hw_v1[0] != 0x57u
        || k_ninlil_lab_approved_reg_v1[0] != 0x47u) {
        emit("ERR profile_missing");
        return 1;
    }

    /* R7 crypto provider — real path linked (mbedTLS). */
    (void)memset(&g_r7_crypto, 0, sizeof(g_r7_crypto));
    rst = ninlil_r7_crypto_mbedtls_provider_init(&g_r7_crypto);
    if (rst != NINLIL_R7_CRYPTO_OK || g_r7_crypto.sha256 == NULL) {
        emit("ERR r7_crypto");
        return 1;
    }

    (void)memset(&clock_cfg, 0, sizeof(clock_cfg));
    (void)memset(&ent_cfg, 0, sizeof(ent_cfg));
    authority_entropy = ninlil_esp_idf_radio_drbg_ops(&g_radio_drbg);
    if (g_radio_entropy_transition_attempted != 0u) {
        if (authority_entropy == NULL) {
            emit("ERR entropy_retired");
            return 1;
        }
        reuse_runtime_entropy = 1u;
    } else {
        if (authority_entropy != NULL) {
            emit("ERR entropy_phase");
            return 1;
        }
        reuse_runtime_entropy = 0u;
    }
    if (reuse_runtime_entropy == 0u) {
        /* First authority owner: mint the one boot clock and seed source. */
        (void)memset(&g_clock, 0, sizeof(g_clock));
        clock_cfg.abi_version = NINLIL_ABI_VERSION;
        clock_cfg.struct_size = (uint16_t)sizeof(clock_cfg);
        rnd = esp_random();
        for (i = 0u; i < 16u; ++i) {
            clock_cfg.boot_epoch_id.bytes[i] =
                (uint8_t)((rnd >> ((i % 4u) * 8u)) + (uint8_t)i + 1u);
        }
        if (ninlil_esp_idf_clock_init(&g_clock, &clock_cfg) != 0) {
            emit("ERR clock");
            return 1;
        }
        (void)memset(&g_entropy, 0, sizeof(g_entropy));
        ent_cfg.abi_version = NINLIL_ABI_VERSION;
        ent_cfg.struct_size = (uint16_t)sizeof(ent_cfg);
        ent_cfg.policy = NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG;
        if (ninlil_esp_idf_entropy_init(&g_entropy, &ent_cfg) != 0) {
            emit("ERR entropy");
            return 1;
        }
        authority_entropy = ninlil_esp_idf_entropy_ops(&g_entropy);
    } else if (ninlil_esp_idf_clock_ops(&g_clock) == NULL) {
        emit("ERR clock_reuse");
        return 1;
    }

    /* Release mode requires flash FULL. Session storage is an explicit,
     * default-off diagnostic profile only. */
    g_ledger_is_flash = 0;
    g_flash_binding = NULL;
    g_ledger_ops = NULL;
#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
    if (session_ledger_init() != 0) {
        emit("ERR ledger_diag_psram");
        return 1;
    }
    emit("WARN ledger=session_diag restart_durable=false not_release");
#else
    {
        ninlil_port_esp_storage_config_t scfg;
        ninlil_port_esp_storage_config_production(&scfg);
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
        scfg.max_namespaces =
            NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES;
#endif
        if (ninlil_port_esp_storage_flash_bind(
                "ninlil_st", &scfg, &g_flash_binding, &g_ledger_ops)
                != 0
            || g_ledger_ops == NULL) {
            /* V1 release HIL: flash FULL required; no session fallback. */
            g_flash_binding = NULL;
            g_ledger_ops = NULL;
            emit("ERR flash_full_required");
            return 1;
        } else {
            g_ledger_is_flash = 1;
        }
    }
#endif

    g_pcp_obj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    if (ninlil_pcp_init_object(&g_pcp_obj, &g_pcp) != NINLIL_PCP_OK) {
        emit("ERR pcp_init");
        return 1;
    }
    if (ninlil_pcp_bind_storage(g_pcp, g_ledger_ops, &perr) != NINLIL_PCP_OK
        || ninlil_pcp_bind_clock(g_pcp, ninlil_esp_idf_clock_ops(&g_clock), &perr)
            != NINLIL_PCP_OK
        || ninlil_pcp_bind_entropy(g_pcp, authority_entropy, &perr)
            != NINLIL_PCP_OK) {
        emit("ERR pcp_bind");
        return 1;
    }

    g_r5_obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    if (ninlil_r5_init_object(&g_r5_obj, &g_r5) != NINLIL_R5_OK) {
        emit("ERR r5_init");
        return 1;
    }
    if (ninlil_r5_load_hardware_profile(
            g_r5,
            k_ninlil_lab_approved_hw_v1,
            sizeof(k_ninlil_lab_approved_hw_v1),
            &rerr)
        != NINLIL_R5_OK) {
        emit("ERR r5_hw");
        return 1;
    }
    if (ninlil_r5_load_regulatory_profile(
            g_r5,
            k_ninlil_lab_approved_reg_v1,
            sizeof(k_ninlil_lab_approved_reg_v1),
            &rerr)
        != NINLIL_R5_OK) {
        emit("ERR r5_reg");
        return 1;
    }
    if (ninlil_r5_activate_profiles(g_r5, &rerr) != NINLIL_R5_OK) {
        emit("ERR r5_activate");
        return 1;
    }
    g_profile_loaded = 1;

    make_site_assignment(&assign);
    if (ninlil_r5_bind_site_assignment(g_r5, &assign, &rerr) != NINLIL_R5_OK) {
        emit("ERR r5_assign");
        return 1;
    }
    (void)memset(&g_live, 0, sizeof(g_live));
    if (ninlil_r5_build_live_binding(g_r5, &g_live, &rerr)
        != NINLIL_R5_OK) {
        emit("ERR r5_live");
        return 1;
    }
    if (ninlil_pcp_bind_live_profile(g_pcp, &g_live, &perr)
        != NINLIL_PCP_OK) {
        emit("ERR pcp_live");
        return 1;
    }
    for (i = 0u; i < 16u; ++i) {
        seed.bytes[i] = (uint8_t)(0xA0u + i);
    }
    /* Restart recovery: recover durable meta if present; else publish once. */
    g_pcp_recovered = 0;
    {
        ninlil_pcp_status_t rst = ninlil_pcp_recover(g_pcp, &perr);
        if (rst == NINLIL_PCP_OK) {
            g_pcp_recovered = 1;
        } else if (rst != NINLIL_PCP_EMPTY_OK) {
            /* Non-empty failure on release flash is fail-closed. */
            if (g_ledger_is_flash != 0) {
                emit("ERR pcp_recover");
                return 1;
            }
        }
    }
    if (g_pcp->published == 0u) {
        if (ninlil_pcp_publish_initial_meta(g_pcp, &seed, &perr) != NINLIL_PCP_OK) {
            emit("ERR pcp_publish");
            return 1;
        }
    }
    if (reuse_runtime_entropy == 0u
        && radio_entropy_transition(clock_cfg.boot_epoch_id.bytes) != 0) {
        emit("ERR radio_entropy_transition");
        return 1;
    }
    if (ninlil_r5_bind_pcp(g_r5, g_pcp, &rerr) != NINLIL_R5_OK) {
        emit("ERR r5_pcp");
        return 1;
    }
    ninlil_r5_permit_ops(&g_r5_permit_ops);
    g_digest_ops.verify = hil_digest_verify;
    return 0;
}

static int cmd_init(void)
{
    ninlil_sx1262_board_config_t board;
    ninlil_sx1262_error_t err;
    ninlil_esp_idf_sx1262_bus_config_t bus_cfg;
    ninlil_sx1262_status_t st;
    ninlil_radio_hal_error_t herr;
    ninlil_sx1262_phy_irq_ops_t irq_ops;
    ninlil_r5_error_t rerr;
    char boot_hex[33];

    if (authority_init() != 0) {
        return 1;
    }

    if (fill_board_release_profile(&board) != 0) {
        emit("ERR board_profile_xiao_wio_required");
        return 1;
    }
    (void)memset(&bus_cfg, 0, sizeof(bus_cfg));
    bus_cfg.abi_version = NINLIL_ESP_IDF_SX1262_BUS_ABI_VERSION;
    bus_cfg.struct_size = (uint16_t)sizeof(bus_cfg);
    bus_cfg.pin_nss = (int32_t)board.pin_nss;
    bus_cfg.pin_sck = (int32_t)board.pin_sck;
    bus_cfg.pin_mosi = (int32_t)board.pin_mosi;
    bus_cfg.pin_miso = (int32_t)board.pin_miso;
    bus_cfg.pin_reset = (int32_t)board.pin_reset;
    bus_cfg.pin_busy = (int32_t)board.pin_busy;
    bus_cfg.pin_dio1 = (int32_t)board.pin_dio1;
    bus_cfg.pin_ant_sw = (int32_t)board.pin_ant_sw;
    bus_cfg.ant_sw_active_high = board.ant_sw_active_high;
    bus_cfg.spi_host = CONFIG_NINLIL_SX1262_SPI_HOST;
    bus_cfg.spi_clock_hz = 2000000u;
    bus_cfg.spi_timeout_ms = 200u;
    bus_cfg.spi_drain_max_attempts = 3u;

    g_bus = (ninlil_esp_idf_sx1262_bus_t)NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT;
    if (ninlil_esp_idf_sx1262_bus_init(&g_bus, &bus_cfg) != 0) {
        emit("ERR bus_init");
        return 1;
    }
    if (ninlil_esp_idf_sx1262_bus_capability_mode(&g_bus)
        != NINLIL_ESP_IDF_SX1262_BUS_CAP_CONTROL_ONLY) {
        emit("ERR bus_cap_default");
        return 1;
    }
    if (ninlil_esp_idf_sx1262_bus_install_dio1_isr(&g_bus) != 0) {
        emit("ERR dio1_isr");
        return 1;
    }
    (void)memset(&g_be_obj, 0, sizeof(g_be_obj));
    st = ninlil_sx1262_init(
        &g_be_obj,
        &board,
        ninlil_esp_idf_sx1262_bus_ops(&g_bus),
        ninlil_esp_idf_sx1262_bus_ctx(&g_bus),
        &g_be,
        &err);
    if (st != NINLIL_SX1262_OK) {
        emit("ERR backend_init");
        return 1;
    }
    if (ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability(&g_bus) != 0) {
        emit("ERR rf_grant");
        return 1;
    }
    if (ninlil_esp_idf_sx1262_bus_capability_mode(&g_bus)
        != NINLIL_ESP_IDF_SX1262_BUS_CAP_RF_SOLE) {
        emit("ERR rf_cap");
        return 1;
    }
    ninlil_sx1262_rf_profile_lab_default(&g_prof);
    /* Align RF profile bounds with approved R5 reg window. */
    g_prof.sf_min = 7u;
    g_prof.sf_max = 9u;
    g_prof.tx_power_mdb_max = 14000;
    g_prof.max_airtime_us_ceiling = 2000000u;

    (void)memset(&irq_ops, 0, sizeof(irq_ops));
    irq_ops.dio1_is_high = ninlil_esp_idf_sx1262_bus_dio1_is_high;
    (void)memset(&g_phy_obj, 0, sizeof(g_phy_obj));
    st = ninlil_sx1262_phy_init(
        &g_phy_obj,
        g_be,
        &g_prof,
        &irq_ops,
        ninlil_esp_idf_sx1262_bus_ctx(&g_bus),
        &g_phy,
        &err);
    if (st != NINLIL_SX1262_OK) {
        emit("ERR phy_init");
        return 1;
    }
    g_edge_obj = (ninlil_sx1262_r9_edge_object_t)NINLIL_SX1262_R9_EDGE_OBJECT_INIT;
    if (ninlil_sx1262_r9_edge_init(
            &g_edge_obj,
            g_phy,
            &g_prof,
            &g_edge,
            &g_edge_ops,
            &g_edge_ctx,
            &herr)
        != NINLIL_RADIO_HAL_OK) {
        emit("ERR edge_init");
        return 1;
    }
    (void)memset(&g_hal_obj, 0, sizeof(g_hal_obj));
    if (ninlil_radio_hal_init_object(&g_hal_obj, &g_hal) != NINLIL_RADIO_HAL_OK
        || ninlil_radio_hal_bind_edge(g_hal, g_edge_ops, g_edge_ctx, &herr)
            != NINLIL_RADIO_HAL_OK
        || ninlil_radio_hal_bind_permit_ops(
               g_hal, &g_r5_permit_ops, g_r5, &herr)
            != NINLIL_RADIO_HAL_OK
        || ninlil_radio_hal_bind_digest_ops(
               g_hal, &g_digest_ops, NULL, &herr)
            != NINLIL_RADIO_HAL_OK) {
        emit("ERR hal_bind");
        return 1;
    }
    if (ninlil_r5_build_live_binding(g_r5, &g_live, &rerr) != NINLIL_R5_OK
        || ninlil_radio_hal_set_live_binding(g_hal, &g_live, &herr)
            != NINLIL_RADIO_HAL_OK) {
        emit("ERR live_bind");
        return 1;
    }
    if (!g_profile_loaded) {
        emit("ERR no_profile");
        return 1;
    }
    g_inited = 1;
    hex16(g_boot_id, boot_hex);
    (void)printf(
        "OK init sole_edge=r1_r2_r5_r9 rf_cap=1 authority=pcp_r5 ledger=%s "
        "pcp_recovered=%u lbt=1 spi_max=%u board=%s "
        "features=tcxo_dio2_ant tcxo_v=0x%02x tcxo_delay=%u "
        "dio2_rf_switch=1 cal_all=1 "
        "pins=nss%u,sck%u,mosi%u,miso%u,rst%u,busy%u,dio1%u,ant%u "
        "boot_id=%s\n",
        g_ledger_is_flash ? "flash_full" : "session_diag",
        (unsigned)g_pcp_recovered,
        (unsigned)NINLIL_ESP_IDF_SX1262_SPI_SCRATCH_BYTES,
        NINLIL_SX1262_BOARD_PROFILE_XIAO_WIO_SX1262_V1_ID,
        (unsigned)board.tcxo_voltage,
        (unsigned)board.tcxo_delay_rtc_steps,
        (unsigned)board.pin_nss,
        (unsigned)board.pin_sck,
        (unsigned)board.pin_mosi,
        (unsigned)board.pin_miso,
        (unsigned)board.pin_reset,
        (unsigned)board.pin_busy,
        (unsigned)board.pin_dio1,
        (unsigned)board.pin_ant_sw,
        boot_hex);
    (void)fflush(stdout);
    return 0;
}

#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
static int v1_class_d_sample(
    ninlil_r2_authority_clock_result_t *out_sample)
{
    ninlil_r2_authority_clock_baseline_result_t baseline;
    ninlil_r2_authority_clock_request_t request;

    (void)memset(&baseline, 0, sizeof(baseline));
    if (ninlil_r2_private_load_authority_clock_baseline(g_pcp, &baseline)
            != 0
        || baseline.published == 0u
        || baseline.trusted_baseline_valid == 0u) {
        return 1;
    }
    (void)memset(&request, 0, sizeof(request));
    (void)memcpy(request.expected_epoch_id,
        baseline.last_trusted_epoch_id, 16u);
    request.watermark_valid = 1u;
    (void)memcpy(request.watermark_epoch_id,
        baseline.last_trusted_epoch_id, 16u);
    request.watermark_now_ms = baseline.last_trusted_now_ms;
    (void)memset(out_sample, 0, sizeof(*out_sample));
    if (ninlil_r2_private_sample_authority_clock(
            g_pcp, &request, out_sample)
            != 0
        || !ninlil_r2_authority_clock_is_class_d(out_sample)) {
        return 1;
    }
    return 0;
}

#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
static int v1_peer_power_of_two(uint32_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static void *v1_peer_allocate(
    void *user, uint64_t size, uint32_t alignment)
{
    size_t actual_alignment;

    (void)user;
    if (size == 0u || size > SIZE_MAX || !v1_peer_power_of_two(alignment)) {
        return NULL;
    }
    actual_alignment = alignment < (uint32_t)sizeof(void *)
        ? sizeof(void *)
        : (size_t)alignment;
    return heap_caps_aligned_alloc(actual_alignment, (size_t)size,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static void v1_peer_deallocate(
    void *user,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
{
    (void)user;
    (void)size;
    (void)alignment;
    if (pointer != NULL) {
        heap_caps_free(pointer);
    }
}

static ninlil_callback_action_t v1_peer_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    (void)token;
    if (delivery == NULL || out_result == NULL
        || delivery->payload.data == NULL || delivery->payload.length == 0u
        || delivery->payload.length > NINLIL_V1_LAB_APPLICATION_MAX) {
        return NINLIL_CALLBACK_FATAL;
    }
    g_v1_peer_delivery_count += 1u;
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t v1_peer_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    if (delivery == NULL || out_result == NULL) {
        return NINLIL_RECONCILE_OUTCOME_UNKNOWN;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->abi_version = NINLIL_ABI_VERSION;
    out_result->struct_size = (uint16_t)sizeof(*out_result);
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    return NINLIL_RECONCILE_KNOWN_RESULT;
}

static int v1_peer_runtime_prepare(void)
{
    ninlil_v1_lab_peer_runtime_config_t runtime_config;
    ninlil_service_callbacks_t callbacks;
    uint32_t workspace_bytes = 0u;
    uint32_t workspace_alignment = 0u;

#if defined(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
    g_v1_peer_ledger = (ninlil_pcp_lab_session_ledger_t *)heap_caps_calloc(
        1u, sizeof(*g_v1_peer_ledger), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_v1_peer_ledger == NULL
        || ninlil_pcp_lab_session_ledger_init(
               g_v1_peer_ledger, &g_v1_peer_storage_ops)
            != 0
        || g_v1_peer_storage_ops == NULL) {
        return 1;
    }
#else
    g_v1_peer_storage_ops = g_ledger_ops;
    if (g_v1_peer_storage_ops == NULL || g_ledger_is_flash == 0) {
        return 1;
    }
#endif
    if (ninlil_composition_v1_workspace_required(
               NINLIL_COMPOSITION_PROFILE_1,
               &workspace_bytes,
               &workspace_alignment)
            != NINLIL_OK
        || workspace_bytes == 0u || workspace_alignment == 0u) {
        return 1;
    }
    g_v1_peer_composition_workspace = heap_caps_aligned_alloc(
        workspace_alignment, workspace_bytes,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (g_v1_peer_composition_workspace == NULL
        || ninlil_esp_idf_execution_init(&g_v1_peer_execution) != 0) {
        return 1;
    }

    (void)memset(&g_v1_peer_allocator, 0, sizeof(g_v1_peer_allocator));
    g_v1_peer_allocator.abi_version = NINLIL_ABI_VERSION;
    g_v1_peer_allocator.struct_size =
        (uint16_t)sizeof(g_v1_peer_allocator);
    g_v1_peer_allocator.allocate = v1_peer_allocate;
    g_v1_peer_allocator.deallocate = v1_peer_deallocate;
    (void)memset(&g_v1_peer_platform, 0, sizeof(g_v1_peer_platform));
    g_v1_peer_platform.abi_version = NINLIL_ABI_VERSION;
    g_v1_peer_platform.struct_size = (uint16_t)sizeof(g_v1_peer_platform);
    g_v1_peer_platform.allocator = &g_v1_peer_allocator;
    g_v1_peer_platform.execution =
        ninlil_esp_idf_execution_ops(&g_v1_peer_execution);
    g_v1_peer_platform.clock = ninlil_esp_idf_clock_ops(&g_clock);
    g_v1_peer_platform.entropy =
        ninlil_esp_idf_radio_drbg_ops(&g_radio_drbg);
    g_v1_peer_platform.storage = g_v1_peer_storage_ops;

    (void)memset(&callbacks, 0, sizeof(callbacks));
    callbacks.abi_version = NINLIL_ABI_VERSION;
    callbacks.struct_size = (uint16_t)sizeof(callbacks);
    callbacks.on_delivery = v1_peer_delivery;
    callbacks.on_reconcile = v1_peer_reconcile;
    (void)memset(&runtime_config, 0, sizeof(runtime_config));
    runtime_config.crypto = &g_r7_crypto;
    runtime_config.platform_template = &g_v1_peer_platform;
    runtime_config.composition_workspace = g_v1_peer_composition_workspace;
    runtime_config.composition_workspace_bytes = workspace_bytes;
    runtime_config.desired_callbacks = &callbacks;
    return ninlil_v1_lab_peer_runtime_prepare(
               &g_v1_peer_runtime, &runtime_config)
            == NINLIL_V1_LAB_PEER_RUNTIME_OK
        ? 0
        : 1;
}
#endif

static int v1_board_init(void)
{
    ninlil_n6_context_pool_t pool;
    ninlil_r2_authority_clock_result_t class_d;
    ninlil_v1_lab_provision_status_t provision_status;
    ninlil_byte_stream_error_t usb_error;
    ninlil_v1_lab_board_owner_config_t owner_config;
    size_t pool_bytes;

    if (cmd_init() != 0) {
        return 1;
    }
    (void)memset(&pool, 0, sizeof(pool));
    pool.max_slots = NINLIL_RADIO_HIL_V1_N6_SLOTS;
    pool_bytes = ninlil_n6_context_pool_bytes(pool.max_slots);
    if (pool_bytes == 0u || pool_bytes > sizeof(g_v1_n6_pool)) {
        emit("ERR v1_n6_pool");
        return 1;
    }
    pool.bytes = g_v1_n6_pool;
    pool.bytes_size = pool_bytes;
    (void)memset(g_v1_n6_object, 0, sizeof(g_v1_n6_object));
    (void)memset(g_v1_n6_pool, 0, sizeof(g_v1_n6_pool));
    if (ninlil_n6_init(g_v1_n6_object, sizeof(g_v1_n6_object),
            &pool, &g_v1_n6)
        != NINLIL_N6_OK) {
        emit("ERR v1_n6_init");
        return 1;
    }
    if (v1_class_d_sample(&class_d) != 0) {
        emit("ERR v1_provisioner");
        return 1;
    }
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    provision_status = ninlil_v1_lab_provisioner_init_peer(&g_v1_provisioner,
        g_v1_n6, g_ledger_ops, ninlil_n6_crypto_host_ops(),
        &g_r7_crypto, &class_d);
#else
    provision_status = ninlil_v1_lab_provisioner_init_controller(
        &g_v1_provisioner, g_v1_n6, g_ledger_ops,
        ninlil_n6_crypto_host_ops(), &g_r7_crypto, &class_d);
#endif
    if (provision_status != NINLIL_V1_LAB_PROVISION_OK) {
        emit("ERR v1_provisioner");
        return 1;
    }
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    if (v1_peer_runtime_prepare() != 0) {
        emit("ERR v1_peer_runtime_prepare");
        return 1;
    }
#endif

    (void)memset(&g_v1_usb_stream, 0, sizeof(g_v1_usb_stream));
    if (ninlil_esp_idf_usb_cdc_init_object(
            &g_v1_usb_object, &g_v1_usb_stream)
        != NINLIL_BYTE_STREAM_OK) {
        emit("ERR v1_usb_init");
        return 1;
    }
    (void)memset(&usb_error, 0, sizeof(usb_error));
    if (ninlil_esp_idf_usb_cdc_open(
            &g_v1_usb_stream, "control-cdc", &usb_error)
        != NINLIL_BYTE_STREAM_OK) {
        emit("ERR v1_usb_open");
        return 1;
    }

    (void)memset(&owner_config, 0, sizeof(owner_config));
    owner_config.usb_stream = &g_v1_usb_stream;
    owner_config.provisioner = &g_v1_provisioner;
    owner_config.crypto = &g_r7_crypto;
    owner_config.local_runtime_id = NULL;
    owner_config.clock = ninlil_esp_idf_clock_ops(&g_clock);
    owner_config.phy = g_phy;
    owner_config.pcp = g_pcp;
    owner_config.hal = g_hal;
    owner_config.live = &g_live;
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    owner_config.data_consumer =
        NINLIL_V1_LAB_BOARD_OWNER_DATA_LOCAL_FABRIC;
    owner_config.pair_ready = ninlil_v1_lab_peer_runtime_pair_ready;
    owner_config.pair_ready_user = &g_v1_peer_runtime;
#else
    owner_config.data_consumer = NINLIL_V1_LAB_BOARD_OWNER_DATA_USB;
#endif
    if (ninlil_v1_lab_board_owner_init(&g_v1_board_owner, &owner_config)
        != NINLIL_V1_LAB_BOARD_OWNER_OK) {
        emit("ERR v1_board_owner");
        return 1;
    }
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    (void)printf(
        "READY v1_board role=peer usb=control-cdc radio=single_hop "
        "runtime=awaiting_binding ledger=%s restart_durable=%s "
        "peer_id=binding\n",
        g_ledger_is_flash != 0 ? "flash_full" : "session_diag",
        g_ledger_is_flash != 0 ? "candidate" : "false");
#else
    (void)printf(
        "READY v1_board role=usb_parent usb=control-cdc radio=single_hop "
        "ledger=%s restart_durable=%s controller_id=binding\n",
        g_ledger_is_flash != 0 ? "flash_full" : "session_diag",
        g_ledger_is_flash != 0 ? "candidate" : "false");
#endif
    (void)fflush(stdout);
    return 0;
}

static void v1_board_run(void)
{
    const ninlil_clock_ops_t *clock = ninlil_esp_idf_clock_ops(&g_clock);
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    uint8_t runtime_ready_reported = 0u;
#endif

    for (;;) {
        ninlil_time_sample_t sample;
        ninlil_v1_lab_board_owner_status_t status;

        (void)memset(&sample, 0, sizeof(sample));
        if (clock == NULL || clock->now == NULL
            || clock->now(clock->user, &sample) != NINLIL_PORT_OK) {
            emit("ERR v1_board_clock");
            break;
        }
        status = ninlil_v1_lab_board_owner_step(
            &g_v1_board_owner, sample.now_ms, 5u);
        if (status != NINLIL_V1_LAB_BOARD_OWNER_OK
            && status != NINLIL_V1_LAB_BOARD_OWNER_BUSY
            && status != NINLIL_V1_LAB_BOARD_OWNER_LINK_DOWN) {
            (void)printf("ERR v1_board_step status=%u\n", (unsigned)status);
            (void)fflush(stdout);
            break;
        }
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
        {
            ninlil_v1_lab_peer_runtime_status_t runtime_status =
                ninlil_v1_lab_peer_runtime_step(&g_v1_peer_runtime);

            if (runtime_status == NINLIL_V1_LAB_PEER_RUNTIME_OK) {
                if (runtime_ready_reported == 0u) {
                    emit("READY v1_peer_runtime services=binding "
                         "fabric=single_hop");
                    runtime_ready_reported = 1u;
                }
            } else if (runtime_status
                != NINLIL_V1_LAB_PEER_RUNTIME_WAITING) {
                (void)printf("ERR v1_peer_runtime_step status=%u\n",
                    (unsigned)runtime_status);
                (void)fflush(stdout);
                break;
            }
        }
#endif
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
#endif

/*
 * Same-session PCP recover on the live g_pcp object.
 * NOT a reboot/restart recovery claim — see PREPARE_TWO_BOOT / COMPLETE_TWO_BOOT.
 */
static int cmd_pcp_recover_same_session(void)
{
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t st;
    char boot_hex[33];

    if (!g_inited || g_pcp == NULL || g_ledger_is_flash == 0) {
        emit("ERR pcp_recover_same_session_not_flash");
        return 1;
    }
    st = ninlil_pcp_recover(g_pcp, &perr);
    hex16(g_boot_id, boot_hex);
    if (st == NINLIL_PCP_OK) {
        g_pcp_same_session_recover_ok = 1;
        (void)printf(
            "OK pcp_recover_same_session status=ok published=%u "
            "ledger=flash_full boot_id=%s claim=same_session_not_restart\n",
            (unsigned)g_pcp->published,
            boot_hex);
        (void)fflush(stdout);
        return 0;
    }
    if (st == NINLIL_PCP_EMPTY_OK) {
        g_pcp_same_session_recover_ok = 1;
        (void)printf(
            "OK pcp_recover_same_session status=empty published=%u "
            "ledger=flash_full boot_id=%s claim=same_session_not_restart\n",
            (unsigned)g_pcp->published,
            boot_hex);
        (void)fflush(stdout);
        return 0;
    }
    (void)printf(
        "ERR pcp_recover_same_session status=%u reason=%u\n",
        (unsigned)st,
        (unsigned)perr.reason);
    return 1;
}

static int cmd_boot_identity(void)
{
    char boot_hex[33];
    int receipt_valid = 0;

    hex16(g_boot_id, boot_hex);
    if (g_two_boot_rtc.magic == NINLIL_RADIO_HIL_TWO_BOOT_MAGIC
        && g_two_boot_rtc.checksum == two_boot_checksum(&g_two_boot_rtc)) {
        receipt_valid = 1;
    }
    (void)printf(
        "OK boot_identity boot_id=%s reset_reason=%u boot_seq=%u "
        "two_boot_receipt=%s two_boot_completed=%u "
        "physical_two_boot_pass=false physical_powercut_pass=false\n",
        boot_hex,
        (unsigned)g_reset_reason,
        (unsigned)g_boot_seq,
        receipt_valid ? "present" : "absent",
        (unsigned)g_two_boot_completed);
    (void)fflush(stdout);
    return 0;
}

static int cmd_prepare_two_boot(void)
{
    char boot_hex[33];
    char fence_hex[9];
    uint32_t fence;

    if (!g_inited || g_pcp == NULL || g_ledger_is_flash == 0) {
        emit("ERR prepare_two_boot_not_ready");
        return 1;
    }
    if (g_pcp->published == 0u) {
        emit("ERR prepare_two_boot_pcp_not_published");
        return 1;
    }
    fence = esp_random();
    if (fence == 0u) {
        fence = 0xC0FFEEu;
    }
    (void)memset(&g_two_boot_rtc, 0, sizeof(g_two_boot_rtc));
    g_two_boot_rtc.magic = NINLIL_RADIO_HIL_TWO_BOOT_MAGIC;
    (void)memcpy(g_two_boot_rtc.prev_boot_id, g_boot_id, 16u);
    g_two_boot_rtc.pcp_published = (uint32_t)g_pcp->published;
    g_two_boot_rtc.fence = fence;
    g_two_boot_rtc.reset_reason_prepare = g_reset_reason;
    g_two_boot_rtc.checksum = two_boot_checksum(&g_two_boot_rtc);
    g_two_boot_prepared = 1;
    hex16(g_boot_id, boot_hex);
    (void)snprintf(
        fence_hex,
        sizeof(fence_hex),
        "%08x",
        (unsigned)fence);
    (void)printf(
        "OK prepare_two_boot receipt=valid boot_id=%s fence=%s "
        "pcp_published=%u ledger=flash_full "
        "class=old claim=awaiting_reboot "
        "physical_two_boot_pass=false\n",
        boot_hex,
        fence_hex,
        (unsigned)g_two_boot_rtc.pcp_published);
    (void)fflush(stdout);
    return 0;
}

static int cmd_reboot(void)
{
    if (g_two_boot_prepared == 0
        || g_two_boot_rtc.magic != NINLIL_RADIO_HIL_TWO_BOOT_MAGIC
        || g_two_boot_rtc.checksum != two_boot_checksum(&g_two_boot_rtc)) {
        emit("ERR reboot_requires_prepare_two_boot");
        return 1;
    }
    emit("OK reboot triggering_esp_restart class=fence_hold");
    vTaskDelay(pdMS_TO_TICKS(50));
    esp_restart();
    return 0; /* unreachable */
}

/*
 * Post-reboot: reconstruct fresh authority from flash FULL and classify
 * old/new/fenced identities. Rejects unchanged boot_id (false restart).
 */
static int cmd_complete_two_boot(const char *prev_boot_hex)
{
    uint8_t prev[16];
    ninlil_pcp_error_t perr;
    ninlil_pcp_status_t st;
    char old_hex[33];
    char new_hex[33];
    char fence_hex[9];
    int i;

    if (prev_boot_hex == NULL || !parse_hex16(prev_boot_hex, prev)) {
        emit("ERR complete_two_boot_bad_prev");
        return 1;
    }
    if (g_two_boot_rtc.magic != NINLIL_RADIO_HIL_TWO_BOOT_MAGIC
        || g_two_boot_rtc.checksum != two_boot_checksum(&g_two_boot_rtc)) {
        emit("ERR complete_two_boot_no_receipt");
        return 1;
    }
    for (i = 0; i < 16; ++i) {
        if (g_two_boot_rtc.prev_boot_id[i] != prev[i]) {
            emit("ERR complete_two_boot_prev_mismatch");
            return 1;
        }
    }
    /* Reject same-session / unchanged boot identity (not a real restart). */
    if (memcmp(g_boot_id, prev, 16u) == 0) {
        emit("ERR complete_two_boot_boot_id_unchanged not_restart");
        return 1;
    }
    if (memcmp(g_two_boot_rtc.prev_boot_id, g_boot_id, 16u) == 0) {
        emit("ERR complete_two_boot_receipt_boot_id_collision");
        return 1;
    }

    /*
     * Fresh reconstruct: tear down live RAM authority and rebuild from flash.
     * Refuse to treat reused g_pcp as restart evidence.
     */
    g_inited = 0;
    g_profile_loaded = 0;
    g_pcp = NULL;
    g_r5 = NULL;
    g_hal = NULL;
    g_edge = NULL;
    g_phy = NULL;
    g_be = NULL;
    g_ledger_ops = NULL;
    g_flash_binding = NULL;
    g_ledger_is_flash = 0;
    g_pcp_recovered = 0;
    g_pcp_same_session_recover_ok = 0;

    if (authority_init() != 0) {
        emit("ERR complete_two_boot_authority_reconstruct");
        return 1;
    }
    if (g_ledger_is_flash == 0 || g_pcp == NULL) {
        emit("ERR complete_two_boot_flash_required");
        return 1;
    }
    st = ninlil_pcp_recover(g_pcp, &perr);
    if (st != NINLIL_PCP_OK && st != NINLIL_PCP_EMPTY_OK) {
        (void)printf(
            "ERR complete_two_boot_pcp_recover status=%u reason=%u\n",
            (unsigned)st,
            (unsigned)perr.reason);
        return 1;
    }
    g_pcp_recovered = (st == NINLIL_PCP_OK) ? 1 : 0;
    g_two_boot_completed = 1;
    hex16(g_two_boot_rtc.prev_boot_id, old_hex);
    hex16(g_boot_id, new_hex);
    (void)snprintf(
        fence_hex, sizeof(fence_hex), "%08x", (unsigned)g_two_boot_rtc.fence);
    /* Consume receipt so it cannot be replayed as a second PASS. */
    g_two_boot_rtc.magic = 0u;
    g_two_boot_rtc.checksum = 0u;
    (void)printf(
        "OK complete_two_boot class=old/new/fenced old_boot_id=%s "
        "new_boot_id=%s fence=%s pcp_recover=%s ledger=flash_full "
        "reconstruct=fresh_authority "
        "physical_two_boot_pass=software_reboot_only "
        "physical_powercut_pass=false rf_hil_pass=false\n",
        old_hex,
        new_hex,
        fence_hex,
        (st == NINLIL_PCP_OK) ? "ok" : "empty");
    (void)fflush(stdout);
    return 0;
}

static int cmd_tx_data(const uint8_t *frame, uint32_t len)
{
    ninlil_r5_issue_plan_t plan;
    ninlil_r5_bind_plan_t full;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_radio_hal_frame_view_t fv;
    ninlil_radio_hal_error_t herr;
    ninlil_radio_hal_status_t st;
    ninlil_r5_error_t rerr;
    ninlil_sx1262_error_t bare_err;
    ninlil_time_sample_t sample;
    ninlil_airtime_lora_input_t ain;
    uint8_t bare[2] = {0x00u, 0x00u};
    uint64_t now_ms = 0u;

    if (!g_inited || g_hal == NULL || g_r5 == NULL || !g_profile_loaded) {
        emit("ERR not_init");
        return 1;
    }
    /* Prove bare R4 still deny on production composition. */
    if (ninlil_sx1262_request_transmit(g_be, bare, 2u, &bare_err)
        != NINLIL_SX1262_TX_DENIED) {
        emit("ERR r4_deny_broken");
        return 1;
    }

    if (ninlil_esp_idf_clock_ops(&g_clock)->now(
            ninlil_esp_idf_clock_ops(&g_clock)->user, &sample)
        != NINLIL_PORT_OK) {
        emit("ERR clock_sample");
        return 1;
    }
    now_ms = sample.now_ms;

    (void)memset(&plan, 0, sizeof(plan));
    plan.frame_bytes = frame;
    plan.frame_byte_length = len;
    if (!sha_frame(frame, len, plan.frame_digest)) {
        emit("ERR digest");
        return 1;
    }
    plan.frame_digest_algorithm = 1u;
    (void)memset(&ain, 0, sizeof(ain));
    ain.sf = 7u;
    ain.cr = 1u;
    ain.header_implicit = NINLIL_AIRTIME_HEADER_EXPLICIT;
    ain.crc_on = NINLIL_AIRTIME_CRC_ON;
    ain.ldro = NINLIL_AIRTIME_LDRO_AUTO;
    ain.payload_len_bytes = (uint8_t)(len > 255u ? 255u : len);
    ain.preamble_len_symbols = 8u;
    ain.bw_hz = 125000u;
    plan.airtime_in = ain;
    plan.not_before_ms = now_ms;
    plan.expiry_ms = now_ms + 600000u;
    {
        ninlil_airtime_result_t aout;
        if (ninlil_airtime_lora_us(&ain, &aout) != NINLIL_AIRTIME_OK) {
            emit("ERR airtime");
            return 1;
        }
        (void)aout;
    }

    (void)memset(&full, 0, sizeof(full));
    (void)memset(&permit, 0, sizeof(permit));
    if (ninlil_r5_issue(g_r5, &plan, &full, &permit, &rerr) != NINLIL_R5_OK) {
        (void)printf(
            "ERR r5_issue status=%u reason=%u item=%u\n",
            (unsigned)rerr.status,
            (unsigned)rerr.reason,
            (unsigned)rerr.bind_item);
        return 1;
    }

    fv.bytes = frame;
    fv.length = len;
    st = ninlil_radio_hal_transmit_with_permit(g_hal, &permit, &fv, &herr);
    if (st != NINLIL_RADIO_HAL_OK) {
        (void)printf(
            "ERR tx status=%u stage=%u reason=%u\n",
            (unsigned)st,
            (unsigned)herr.stage,
            (unsigned)herr.reason);
        return 1;
    }
    emit("OK tx_armed sole_edge authority=r5_pcp lbt=1");
    return 0;
}

static void handle_line(char *line)
{
    size_t n = strlen(line);
    while (n > 0u && (line[n - 1u] == '\n' || line[n - 1u] == '\r')) {
        line[--n] = '\0';
    }
    if (strcmp(line, "INIT") == 0) {
        (void)cmd_init();
        return;
    }
    if (strcmp(line, "POLL") == 0) {
        ninlil_sx1262_error_t err;
        ninlil_sx1262_status_t st;
        if (!g_inited || g_phy == NULL) {
            emit("ERR not_init");
            return;
        }
        st = ninlil_sx1262_phy_poll(g_phy, &err);
        if (st != NINLIL_SX1262_OK) {
            (void)printf(
                "ERR poll status=%u stage=%u reason=%u\n",
                (unsigned)st,
                (unsigned)err.stage,
                (unsigned)err.reason);
            return;
        }
        (void)printf(
            "OK poll state=%u gen=%llu cap=%u\n",
            (unsigned)ninlil_sx1262_phy_state(g_phy),
            (unsigned long long)ninlil_sx1262_phy_generation(g_phy),
            (unsigned)ninlil_esp_idf_sx1262_bus_capability_mode(&g_bus));
        return;
    }
    if (strcmp(line, "RECOVER") == 0) {
        ninlil_sx1262_error_t err;
        ninlil_sx1262_status_t st;
        if (!g_inited || g_phy == NULL) {
            emit("ERR not_init");
            return;
        }
        st = ninlil_sx1262_phy_recover(g_phy, &err);
        if (st != NINLIL_SX1262_OK) {
            (void)printf(
                "ERR recover status=%u stage=%u reason=%u\n",
                (unsigned)st,
                (unsigned)err.stage,
                (unsigned)err.reason);
            return;
        }
        emit("OK recover");
        return;
    }
    if (strcmp(line, "PCP_RECOVER_SAME_SESSION") == 0) {
        (void)cmd_pcp_recover_same_session();
        return;
    }
    /* Legacy alias: same-session only; never a restart claim. */
    if (strcmp(line, "RECOVER_PCP") == 0) {
        (void)cmd_pcp_recover_same_session();
        return;
    }
    if (strcmp(line, "BOOT_IDENTITY") == 0) {
        (void)cmd_boot_identity();
        return;
    }
    if (strcmp(line, "PREPARE_TWO_BOOT") == 0) {
        (void)cmd_prepare_two_boot();
        return;
    }
    if (strcmp(line, "REBOOT") == 0) {
        (void)cmd_reboot();
        return;
    }
    if (strncmp(line, "COMPLETE_TWO_BOOT ", 18) == 0) {
        (void)cmd_complete_two_boot(line + 18);
        return;
    }
    if (strcmp(line, "COMPLETE_TWO_BOOT") == 0) {
        emit("ERR complete_two_boot_needs_prev_boot_id");
        return;
    }
    if (strcmp(line, "RX_START") == 0) {
        ninlil_sx1262_error_t err;
        if (!g_inited || g_phy == NULL) {
            emit("ERR not_init");
            return;
        }
        if (ninlil_sx1262_phy_start_rx(g_phy, 5000u, &err) != NINLIL_SX1262_OK) {
            emit("ERR rx");
            return;
        }
        emit("OK rx_start");
        return;
    }
    if (strcmp(line, "RX_TAKE") == 0) {
        ninlil_sx1262_error_t err;
        ninlil_sx1262_rx_meta_t meta;
        ninlil_sx1262_status_t st;
        uint32_t i;
        if (!g_inited || g_phy == NULL) {
            emit("ERR not_init");
            return;
        }
        st = ninlil_sx1262_phy_take_rx(
            g_phy, g_rx_frame, (uint32_t)sizeof(g_rx_frame), &meta, &err);
        if (st != NINLIL_SX1262_OK) {
            (void)printf(
                "ERR rx_take status=%u stage=%u reason=%u\n",
                (unsigned)st,
                (unsigned)err.stage,
                (unsigned)err.reason);
            return;
        }
        (void)printf(
            "OK rx_take class=%u len=%u rssi=%d snr=%d irq=0x%x gen=%llu payload=",
            (unsigned)meta.classification,
            (unsigned)meta.length,
            (int)meta.rssi_dbm,
            (int)meta.snr_db,
            (unsigned)meta.irq_status,
            (unsigned long long)meta.radio_generation);
        for (i = 0u; i < meta.length && i < sizeof(g_rx_frame); ++i) {
            (void)printf("%02x", (unsigned)g_rx_frame[i]);
        }
        (void)printf("\n");
        (void)fflush(stdout);
        return;
    }
    if (strncmp(line, "TX_DATA ", 8) == 0) {
        const char *hex = line + 8;
        uint8_t frame[64];
        uint32_t len = 0u;
        while (hex[0] != '\0' && hex[1] != '\0' && len < sizeof(frame)) {
            unsigned v = 0u;
            if (sscanf(hex, "%2x", &v) != 1) {
                break;
            }
            frame[len++] = (uint8_t)v;
            hex += 2;
            if (*hex == ' ') {
                hex += 1;
            }
        }
        if (len == 0u) {
            emit("ERR empty_frame");
            return;
        }
        (void)cmd_tx_data(frame, len);
        return;
    }
    if (strcmp(line, "PING") == 0) {
        emit("OK pong");
        return;
    }
    if (strcmp(line, "STATS") == 0) {
        ninlil_sx1262_r9_edge_stats_t est;
        ninlil_pcp_r2_stats_t pst;
        if (!g_inited || g_edge == NULL || g_pcp == NULL) {
            emit("ERR not_init");
            return;
        }
        ninlil_sx1262_r9_edge_stats(g_edge, &est);
        ninlil_pcp_stats(g_pcp, &pst);
        (void)printf(
            "OK stats edge_ok=%llu digest_rej=%llu airtime_rej=%llu "
            "pcp_issue=%llu pcp_consume=%llu cap=%u profile=%u ledger=%s\n",
            (unsigned long long)est.edge_ok,
            (unsigned long long)est.digest_reject,
            (unsigned long long)est.airtime_reject,
            (unsigned long long)pst.issue_ok,
            (unsigned long long)pst.consume_ok,
            (unsigned)ninlil_esp_idf_sx1262_bus_capability_mode(&g_bus),
            (unsigned)g_profile_loaded,
            g_ledger_is_flash ? "flash_full" : "session_diag");
        return;
    }
    if (strcmp(line, "MFDT_PING") == 0) {
        emit("OK mfdt_stub residual=H50_HARDWARE");
        return;
    }
    if (strcmp(line, "MFDT_STATUS") == 0) {
        emit("OK mfdt_status private_default_off not_hil powercut_residual=true");
        return;
    }
    if (strncmp(line, "MFDT_", 5) == 0) {
        emit("ERR mfdt_not_wired residual=H50_HARDWARE");
        return;
    }
    emit("ERR unknown");
}

void app_main(void)
{
    char line[256];
    size_t pos = 0u;
    char boot_hex[33];

    mint_boot_identity();
    hex16(g_boot_id, boot_hex);
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_BOARD)
#if defined(CONFIG_NINLIL_RADIO_HIL_V1_PEER)
    ESP_LOGI(TAG, "starting V1 generic peer diagnostic profile");
#else
    ESP_LOGI(TAG, "starting V1 USB parent diagnostic profile");
#endif
    if (v1_board_init() != 0) {
        emit("ERR v1_board_startup");
        for (;;) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    v1_board_run();
    return;
#endif
    ESP_LOGI(
        TAG,
        "radio_hil sole_edge R1+R2+R5+R9 RF_SOLE; stack sized for PCP/R5 path");
    /* Honest nonclaims at boot (physical power-cut / two-boot remain NOT_RUN
     * until device protocol proves them). */
    (void)printf(
        "READY radio_hil sole_edge=r1_r2_r5_r9 authority=real "
        "board=%s "
        "rf_hil_pass=false japan_legal=false physical_powercut_pass=false "
        "physical_two_boot_pass=false same_session_recover_is_not_restart=true "
        "ledger_policy=flash_full_required boot_id=%s reset_reason=%u\n",
        NINLIL_SX1262_BOARD_PROFILE_XIAO_WIO_SX1262_V1_ID,
        boot_hex,
        (unsigned)g_reset_reason);
    (void)fflush(stdout);
    for (;;) {
        int c = getchar();
        if (c == EOF) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (c == '\n' || c == '\r') {
            if (pos > 0u) {
                line[pos] = '\0';
                handle_line(line);
                pos = 0u;
            }
            continue;
        }
        if (pos + 1u < sizeof(line)) {
            line[pos++] = (char)c;
        }
    }
}
