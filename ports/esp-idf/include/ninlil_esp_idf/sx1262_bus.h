#ifndef NINLIL_ESP_IDF_SX1262_BUS_H
#define NINLIL_ESP_IDF_SX1262_BUS_H

/*
 * ESP-IDF production-private SX1262 bus.
 *
 * Default mode: R4 control-plane only (RF emission opcodes denied at SPI).
 * Optional single-shot RF_SOLE capability: closed R9 opcode set for the sole
 * physical edge (R1 radio_hal → R9 edge → phy_arm_tx). Grant is private and
 * call-site gated; R4 bare request_transmit remains TX_DENIED.
 *
 * Finite SPI: queue_trans + get_trans_result (no polling_transmit/portMAX_DELAY).
 * Pending ownership: get_result timeout keeps descriptor until drain (docs/28 §6.4).
 *
 * spi_drain_max_attempts: 0 → default 3; else closed range **1..16**.
 * Shutdown drain wait ≤ attempts * spi_timeout_ms (finite).
 *
 * SHUTDOWN_REBOOT_REQUIRED — caller MUST (docs/28 §6.4):
 *   - Keep the entire bus object (incl. trans_storage, tx_scratch, rx_scratch)
 *     alive and **immutable** until device reboot completes.
 *   - MUST NOT free, reuse, memset, or re-init the object storage: late SPI/DMA
 *     completion may still write into those buffers (use-after-free ban).
 *
 * Nonclaims: not RF HIL PASS, not legal, not public include/ninlil.
 */

#include <stddef.h>
#include <stdint.h>

#include "ninlil_sx1262_backend.h"
#include "ninlil_sx1262_bus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_SX1262_BUS_ABI_VERSION ((uint16_t)0x0005u)
#define NINLIL_ESP_IDF_SX1262_BUS_MAGIC ((uint32_t)0x45325350u) /* 'E2SP' */

/* Capability modes (must match sx1262_rf_bus_capability_logic). */
#define NINLIL_ESP_IDF_SX1262_BUS_CAP_CONTROL_ONLY ((uint32_t)0u)
#define NINLIL_ESP_IDF_SX1262_BUS_CAP_RF_SOLE ((uint32_t)1u)

/* Max SPI frame length (WriteBuffer + payload); matches phy SPI_CAP. */
#define NINLIL_ESP_IDF_SX1262_SPI_SCRATCH_BYTES ((size_t)280u)

/*
 * Caller MUST zero-init before first init (do not pass uninitialized storage):
 *   ninlil_esp_idf_sx1262_bus_t bus = NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT;
 * Uninitialized lifecycle is never treated as authoritative without magic==0.
 */
#define NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT {0}

/* lifecycle field values (also used by pure ownership SM). */
#define NINLIL_ESP_IDF_SX1262_BUS_LIFE_ZERO ((uint32_t)0u)
#define NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE ((uint32_t)1u)
#define NINLIL_ESP_IDF_SX1262_BUS_LIFE_SHUTDOWN ((uint32_t)2u)
/* Drain budget exhausted with outstanding SPI descriptor — hold HW; reboot. */
#define NINLIL_ESP_IDF_SX1262_BUS_LIFE_REBOOT_REQUIRED ((uint32_t)3u)

/* Shutdown return codes. */
#define NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_OK ((int)0)
#define NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED ((int)1)
#define NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_FAIL ((int)2)

typedef struct ninlil_esp_idf_sx1262_bus_config {
    uint16_t abi_version;
    uint16_t struct_size;
    int32_t pin_nss;
    int32_t pin_sck;
    int32_t pin_mosi;
    int32_t pin_miso;
    int32_t pin_reset;
    int32_t pin_busy;
    int32_t pin_dio1;
    int32_t pin_ant_sw; /* -1 if unused */
    /* 1 = active-high, 0 = active-low; ignored when pin_ant_sw < 0 (must be 0). */
    uint8_t ant_sw_active_high;
    uint8_t reserved0[3];
    int32_t spi_host;
    uint32_t spi_clock_hz;   /* 1..16e6 */
    uint32_t spi_timeout_ms; /* finite; required non-zero; ≠ BUSY timeout */
    /*
     * Drain budget after get_trans_result timeout:
     *   0 → default 3; else must be 1..16 (reject outside).
     */
    uint32_t spi_drain_max_attempts;
    uint32_t reserved_zero;
} ninlil_esp_idf_sx1262_bus_config_t;

/*
 * SPI transaction storage: portable header must not include ESP-IDF SPI types.
 * Scratch sized for R9 WriteBuffer (frame + opcode header).
 */
#define NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES ((size_t)64u)

typedef struct ninlil_esp_idf_sx1262_bus {
    uint32_t magic;      /* 0 = zero-init / never successfully inited */
    uint32_t lifecycle;  /* ZERO only trusted when magic==0 (OBJECT_INIT) */
    uint32_t poisoned;   /* SPI fail-closed — no further xfer */
    uint32_t pending_state; /* pure SM pend mirror (see pending_logic) */
    uint32_t drain_attempts;
    uint32_t max_drain_attempts;
    /*
     * SPI capability: CONTROL_ONLY (default) or RF_SOLE after single-shot grant.
     * Pure policy: sx1262_rf_bus_capability_logic.
     */
    uint32_t capability_mode;
    uint32_t rf_grant_count; /* 0 or 1 (single-shot); stats/proof only */
    ninlil_esp_idf_sx1262_bus_config_t cfg;
    void *spi_handle;
    /* Non-NULL while SPI driver may still complete the queued descriptor. */
    void *pending_trans;
    /*
     * DIO1 IRQ latch: set from ISR (notify only), cleared on dio1_is_high sample
     * from single-owner task. ISR never performs SPI/IRQ status reads.
     */
    volatile uint32_t dio1_irq_latched;
    uint32_t dio1_isr_installed;
    uint8_t tx_scratch[NINLIL_ESP_IDF_SX1262_SPI_SCRATCH_BYTES];
    uint8_t rx_scratch[NINLIL_ESP_IDF_SX1262_SPI_SCRATCH_BYTES];
    _Alignas(max_align_t) uint8_t
        trans_storage[NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES];
    ninlil_sx1262_bus_ops_t ops;
} ninlil_esp_idf_sx1262_bus_t;

/* Host + ESP: storage size and max_align_t placement (no ESP types). */
_Static_assert(
    sizeof(((ninlil_esp_idf_sx1262_bus_t *)0)->trans_storage)
        == NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES,
    "sx1262 trans_storage size");
_Static_assert(
    (offsetof(ninlil_esp_idf_sx1262_bus_t, trans_storage)
        % _Alignof(max_align_t))
        == 0u,
    "sx1262 trans_storage offset must be max_align_t-aligned");
_Static_assert(
    _Alignof(ninlil_esp_idf_sx1262_bus_t) >= _Alignof(max_align_t)
        || (offsetof(ninlil_esp_idf_sx1262_bus_t, trans_storage)
               % _Alignof(max_align_t))
            == 0u,
    "sx1262 bus object preserves trans_storage alignment");
_Static_assert(
    sizeof(((ninlil_esp_idf_sx1262_bus_t *)0)->tx_scratch)
        == NINLIL_ESP_IDF_SX1262_SPI_SCRATCH_BYTES,
    "sx1262 SPI scratch size");

/* Host-testable pure helpers (no FreeRTOS types). */
int ninlil_esp_idf_sx1262_ms_to_ticks(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks);

/* ceil(us * tick_rate / 1e6), min 1 tick; overflow → 0. */
int ninlil_esp_idf_sx1262_us_to_ticks_ceil(
    uint32_t delay_us,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks);

int ninlil_esp_idf_sx1262_bus_init(
    ninlil_esp_idf_sx1262_bus_t *bus,
    const ninlil_esp_idf_sx1262_bus_config_t *config);

/*
 * Drain a TIMEOUT_HELD pending descriptor with finite get_trans_result.
 * Returns 0 if no pending or drain recovered; non-zero if still held / reboot.
 */
int ninlil_esp_idf_sx1262_bus_drain(ninlil_esp_idf_sx1262_bus_t *bus);

/*
 * Shutdown: drain if needed (≤ spi_drain_max_attempts × spi_timeout_ms),
 * then remove_device/free only when safe.
 * Returns:
 *   SHUTDOWN_OK — re-init allowed; object may be reused after clean release
 *   SHUTDOWN_REBOOT_REQUIRED — hold HW **and** bus object storage until reboot
 *     (MUST NOT free/mutate object; late completion may touch buffers)
 *   SHUTDOWN_FAIL — argument/lifecycle error
 */
int ninlil_esp_idf_sx1262_bus_shutdown(ninlil_esp_idf_sx1262_bus_t *bus);

int ninlil_esp_idf_sx1262_bus_reboot_required(
    const ninlil_esp_idf_sx1262_bus_t *bus);

const ninlil_sx1262_bus_ops_t *ninlil_esp_idf_sx1262_bus_ops(
    ninlil_esp_idf_sx1262_bus_t *bus);

void *ninlil_esp_idf_sx1262_bus_ctx(ninlil_esp_idf_sx1262_bus_t *bus);

/*
 * Single-shot private grant of RF_SOLE SPI capability.
 * Production call-site: only R9 sole-edge composition (radio_hil / gate).
 * Returns 0 on success; non-zero if not ACTIVE, already granted, or ISR.
 * Does not issue SetTx; only opens the SPI admit policy for R9 opcodes.
 */
int ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability(
    ninlil_esp_idf_sx1262_bus_t *bus);

/* Revoke RF_SOLE → CONTROL_ONLY (e.g. after recover/shutdown path). */
int ninlil_esp_idf_sx1262_bus_revoke_rf_capability(
    ninlil_esp_idf_sx1262_bus_t *bus);

uint32_t ninlil_esp_idf_sx1262_bus_capability_mode(
    const ninlil_esp_idf_sx1262_bus_t *bus);

/*
 * DIO1 sample for phy irq_ops: GPIO level OR ISR latch (clears latch).
 * Safe from task context only (not from ISR). Returns 0 on success.
 * ISR only latches; single-owner task performs poll / IRQ status SPI.
 */
int ninlil_esp_idf_sx1262_bus_dio1_is_high(void *ctx, int *out_high);

/*
 * Install/remove DIO1 GPIO ISR that latches rising edge for poll path.
 * Returns 0 on success. Composition-owned; not automatic on bus_init.
 */
int ninlil_esp_idf_sx1262_bus_install_dio1_isr(ninlil_esp_idf_sx1262_bus_t *bus);
int ninlil_esp_idf_sx1262_bus_uninstall_dio1_isr(ninlil_esp_idf_sx1262_bus_t *bus);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_SX1262_BUS_H */
