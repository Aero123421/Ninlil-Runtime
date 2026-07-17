#ifndef NINLIL_ESP_IDF_SX1262_BUS_H
#define NINLIL_ESP_IDF_SX1262_BUS_H

/*
 * ESP-IDF production-private SX1262 bus (R4 control-plane).
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
 * Nonclaims: not RF TX, not HIL, not public include/ninlil.
 */

#include <stddef.h>
#include <stdint.h>

#include "ninlil_sx1262_backend.h"
#include "ninlil_sx1262_bus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_ESP_IDF_SX1262_BUS_ABI_VERSION ((uint16_t)0x0003u)
#define NINLIL_ESP_IDF_SX1262_BUS_MAGIC ((uint32_t)0x45325350u) /* 'E2SP' */

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
 * Storage uses C11 max_align_t alignment so the adapter TU may place the host
 * SPI transaction object here (covers Xtensa/ESP-IDF alignment).
 * Size/alignment vs the real ESP SPI transaction type is compile-asserted in
 * ports/esp-idf/src/esp_idf_sx1262_bus.c.
 */
#define NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES ((size_t)64u)

typedef struct ninlil_esp_idf_sx1262_bus {
    uint32_t magic;      /* 0 = zero-init / never successfully inited */
    uint32_t lifecycle;  /* ZERO only trusted when magic==0 (OBJECT_INIT) */
    uint32_t poisoned;   /* SPI fail-closed — no further xfer */
    uint32_t pending_state; /* pure SM pend mirror (see pending_logic) */
    uint32_t drain_attempts;
    uint32_t max_drain_attempts;
    ninlil_esp_idf_sx1262_bus_config_t cfg;
    void *spi_handle;
    /* Non-NULL while SPI driver may still complete the queued descriptor. */
    void *pending_trans;
    uint8_t tx_scratch[16];
    uint8_t rx_scratch[16];
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

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_ESP_IDF_SX1262_BUS_H */
