#ifndef NINLIL_SX1262_BUS_H
#define NINLIL_SX1262_BUS_H

/*
 * R4 abstract bus ops for SX1262 control-plane (portable).
 * No ESP-IDF / FreeRTOS / SPI host types.
 * Production ESP adapter: ports/esp-idf (separate TU).
 * Host spy: tests/support only.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return 0 on success, non-zero on failure.
 * D1 never invents success after a non-zero bus result.
 */
typedef struct ninlil_sx1262_bus_ops {
    int (*reset_assert)(void *ctx);
    int (*reset_deassert)(void *ctx);
    /* *out_high = 1 if BUSY is high (device busy), 0 if low (ready). */
    int (*busy_is_high)(void *ctx, int *out_high);
    /*
     * Full-duplex SPI transfer of len bytes.
     * tx must be non-NULL when len > 0.
     * rx may be NULL (write-only; host still clocks len bytes).
     */
    int (*spi_transfer)(
        void *ctx,
        const uint8_t *tx,
        uint8_t *rx,
        size_t len);
    int (*delay_us)(void *ctx, uint32_t us);
    /* Monotonic millisecond domain for timeouts (may wrap). */
    int (*now_ms)(void *ctx, uint64_t *out_ms);
    /*
     * Optional external antenna switch. Required non-NULL iff board
     * feature ANT_SW_PRESENT is set.
     */
    int (*ant_sw_set)(void *ctx, int active);
} ninlil_sx1262_bus_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_BUS_H */
