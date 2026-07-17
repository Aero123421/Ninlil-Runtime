#ifndef NINLIL_SX1262_SPI_PENDING_LOGIC_H
#define NINLIL_SX1262_SPI_PENDING_LOGIC_H

/*
 * Pure SPI transaction ownership / drain state machine (host + ESP).
 * Models ESP-IDF v5.5.3 get_trans_result timeout: descriptor stays with the
 * driver until result is received; free/remove before drain is forbidden.
 * No FreeRTOS / driver headers.
 *
 * Drain budget (closed):
 *   spi_drain_max_attempts == 0 → default 3
 *   otherwise must be in [1, 16]
 * Shutdown total wait ≤ attempts * spi_timeout_ms (finite, overflow-checked).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bus hardware lifecycle (adapter-facing). */
#define NINLIL_SX1262_SPI_OWN_LIFE_ACTIVE ((uint32_t)1u)
#define NINLIL_SX1262_SPI_OWN_LIFE_SHUTDOWN ((uint32_t)2u)
#define NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED ((uint32_t)3u)

/* Pending descriptor ownership. */
#define NINLIL_SX1262_SPI_PEND_NONE ((uint32_t)0u)
#define NINLIL_SX1262_SPI_PEND_IN_FLIGHT ((uint32_t)1u)
/* get_result timed out: descriptor still owned by SPI driver — must drain. */
#define NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD ((uint32_t)2u)

#define NINLIL_SX1262_SPI_OWN_DEFAULT_MAX_DRAIN ((uint32_t)3u)
#define NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MIN ((uint32_t)1u)
#define NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MAX ((uint32_t)16u)

typedef struct ninlil_sx1262_spi_own {
    uint32_t life;
    uint32_t pend;
    uint32_t poisoned;
    uint32_t drain_attempts;
    uint32_t max_drain_attempts;
} ninlil_sx1262_spi_own_t;

/*
 * Normalize config: 0 → default; 1..16 → as-is; else fail (0).
 * out_max never exceeds MAX_DRAIN_MAX.
 */
int ninlil_sx1262_spi_own_normalize_max_drain(
    uint32_t configured,
    uint32_t *out_max);

/*
 * Upper bound on shutdown drain wait: max_attempts * timeout_ms.
 * Overflow → 0. Proves total wait is finite when config is valid.
 */
int ninlil_sx1262_spi_own_max_drain_wait_ms(
    uint32_t max_drain_attempts,
    uint32_t spi_timeout_ms,
    uint64_t *out_wait_ms);

/*
 * max_drain_attempts must already be normalized (1..16).
 * configured 0 is not accepted here — normalize first.
 */
void ninlil_sx1262_spi_own_reset(
    ninlil_sx1262_spi_own_t *own,
    uint32_t max_drain_attempts);

/* queue_trans succeeded — descriptor now in-flight. */
int ninlil_sx1262_spi_own_on_queued(ninlil_sx1262_spi_own_t *own);

/* get_trans_result OK for the outstanding descriptor. */
int ninlil_sx1262_spi_own_on_result_ok(ninlil_sx1262_spi_own_t *own);

/*
 * get_trans_result timeout / mismatch: keep descriptor ownership (TIMEOUT_HELD),
 * poison further SPI. Never clear pending here.
 */
int ninlil_sx1262_spi_own_on_result_timeout(ninlil_sx1262_spi_own_t *own);

/* Late completion during drain: clear pending; poison remains. */
int ninlil_sx1262_spi_own_on_drain_ok(ninlil_sx1262_spi_own_t *own);

/*
 * Drain attempt still times out. Increments attempts; on budget exhausted
 * → REBOOT_REQUIRED (must hold HW lifetime; re-init forbidden).
 */
int ninlil_sx1262_spi_own_on_drain_timeout(ninlil_sx1262_spi_own_t *own);

/* New SPI transfer allowed only when ACTIVE, unpoisoned, no pending. */
int ninlil_sx1262_spi_own_can_transfer(const ninlil_sx1262_spi_own_t *own);

/* remove_device / bus_free only when no outstanding descriptor. */
int ninlil_sx1262_spi_own_may_release_hw(const ninlil_sx1262_spi_own_t *own);

/*
 * When REBOOT_REQUIRED: caller MUST NOT free/reuse/memset the bus object
 * (incl. trans_storage / scratch) until device reboot — late completion
 * may still write those buffers.
 */
int ninlil_sx1262_spi_own_may_release_object_storage(
    const ninlil_sx1262_spi_own_t *own);

/* Clean HW release completed → SHUTDOWN, re-init allowed. */
void ninlil_sx1262_spi_own_on_hw_released(ninlil_sx1262_spi_own_t *own);

int ninlil_sx1262_spi_own_reinit_allowed(const ninlil_sx1262_spi_own_t *own);

int ninlil_sx1262_spi_own_is_reboot_required(const ninlil_sx1262_spi_own_t *own);

int ninlil_sx1262_spi_own_needs_drain(const ninlil_sx1262_spi_own_t *own);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_SX1262_SPI_PENDING_LOGIC_H */
