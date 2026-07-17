/*
 * Pure SPI pending ownership state machine (docs/28 §6.4).
 * C11 freestanding-friendly: stddef for NULL; stdint via header.
 */

#include "sx1262_spi_pending_logic.h"

#include <stddef.h>

int ninlil_sx1262_spi_own_normalize_max_drain(
    uint32_t configured,
    uint32_t *out_max)
{
    if (out_max == NULL) {
        return 0;
    }
    if (configured == 0u) {
        *out_max = NINLIL_SX1262_SPI_OWN_DEFAULT_MAX_DRAIN;
        return 1;
    }
    if (configured < NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MIN
        || configured > NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MAX) {
        return 0;
    }
    *out_max = configured;
    return 1;
}

int ninlil_sx1262_spi_own_max_drain_wait_ms(
    uint32_t max_drain_attempts,
    uint32_t spi_timeout_ms,
    uint64_t *out_wait_ms)
{
    uint64_t prod;

    if (out_wait_ms == NULL || spi_timeout_ms == 0u
        || max_drain_attempts < NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MIN
        || max_drain_attempts > NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MAX) {
        return 0;
    }
    if (max_drain_attempts > UINT64_MAX / (uint64_t)spi_timeout_ms) {
        return 0;
    }
    prod = (uint64_t)max_drain_attempts * (uint64_t)spi_timeout_ms;
    *out_wait_ms = prod;
    return 1;
}

void ninlil_sx1262_spi_own_reset(
    ninlil_sx1262_spi_own_t *own,
    uint32_t max_drain_attempts)
{
    uint32_t norm;

    if (own == NULL) {
        return;
    }
    /*
     * Prefer normalize; if caller passed raw 0, map to default.
     * Out-of-range non-zero is clamped only if normalize fails after 0-path —
     * callers must validate first; out-of-range → default for fail-closed SM.
     */
    if (!ninlil_sx1262_spi_own_normalize_max_drain(max_drain_attempts, &norm)) {
        norm = NINLIL_SX1262_SPI_OWN_DEFAULT_MAX_DRAIN;
    }
    own->life = NINLIL_SX1262_SPI_OWN_LIFE_ACTIVE;
    own->pend = NINLIL_SX1262_SPI_PEND_NONE;
    own->poisoned = 0u;
    own->drain_attempts = 0u;
    own->max_drain_attempts = norm;
}

int ninlil_sx1262_spi_own_on_queued(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL || own->life != NINLIL_SX1262_SPI_OWN_LIFE_ACTIVE
        || own->poisoned != 0u
        || own->pend != NINLIL_SX1262_SPI_PEND_NONE) {
        return 0;
    }
    own->pend = NINLIL_SX1262_SPI_PEND_IN_FLIGHT;
    return 1;
}

int ninlil_sx1262_spi_own_on_result_ok(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL || own->pend != NINLIL_SX1262_SPI_PEND_IN_FLIGHT) {
        return 0;
    }
    own->pend = NINLIL_SX1262_SPI_PEND_NONE;
    return 1;
}

int ninlil_sx1262_spi_own_on_result_timeout(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL) {
        return 0;
    }
    if (own->pend != NINLIL_SX1262_SPI_PEND_IN_FLIGHT
        && own->pend != NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD) {
        return 0;
    }
    /* Keep ownership of descriptor; poison further transfers. */
    own->pend = NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD;
    own->poisoned = 1u;
    own->drain_attempts = 0u;
    return 1;
}

int ninlil_sx1262_spi_own_on_drain_ok(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL || own->pend != NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD) {
        return 0;
    }
    own->pend = NINLIL_SX1262_SPI_PEND_NONE;
    /* poison stays — bus is fail-closed until clean shutdown/re-init */
    return 1;
}

int ninlil_sx1262_spi_own_on_drain_timeout(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL || own->pend != NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD) {
        return 0;
    }
    if (own->drain_attempts < UINT32_MAX) {
        own->drain_attempts += 1u;
    }
    if (own->drain_attempts >= own->max_drain_attempts) {
        own->life = NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
        own->poisoned = 1u;
        /* pend remains TIMEOUT_HELD — must not free descriptor / remove_device */
    }
    return 1;
}

int ninlil_sx1262_spi_own_can_transfer(const ninlil_sx1262_spi_own_t *own)
{
    return own != NULL && own->life == NINLIL_SX1262_SPI_OWN_LIFE_ACTIVE
        && own->poisoned == 0u && own->pend == NINLIL_SX1262_SPI_PEND_NONE;
}

int ninlil_sx1262_spi_own_may_release_hw(const ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL) {
        return 0;
    }
    if (own->life == NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED) {
        return 0;
    }
    return own->pend == NINLIL_SX1262_SPI_PEND_NONE;
}

int ninlil_sx1262_spi_own_may_release_object_storage(
    const ninlil_sx1262_spi_own_t *own)
{
    /* REBOOT_REQUIRED: late SPI may still DMA into object storage. */
    if (own == NULL) {
        return 0;
    }
    return own->life != NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
}

void ninlil_sx1262_spi_own_on_hw_released(ninlil_sx1262_spi_own_t *own)
{
    if (own == NULL) {
        return;
    }
    own->life = NINLIL_SX1262_SPI_OWN_LIFE_SHUTDOWN;
    own->pend = NINLIL_SX1262_SPI_PEND_NONE;
    own->poisoned = 1u;
}

int ninlil_sx1262_spi_own_reinit_allowed(const ninlil_sx1262_spi_own_t *own)
{
    return own != NULL && own->life == NINLIL_SX1262_SPI_OWN_LIFE_SHUTDOWN
        && own->pend == NINLIL_SX1262_SPI_PEND_NONE;
}

int ninlil_sx1262_spi_own_is_reboot_required(const ninlil_sx1262_spi_own_t *own)
{
    return own != NULL
        && own->life == NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
}

int ninlil_sx1262_spi_own_needs_drain(const ninlil_sx1262_spi_own_t *own)
{
    return own != NULL && own->pend == NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD
        && own->life != NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
}
