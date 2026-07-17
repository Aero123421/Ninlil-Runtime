/*
 * Pure overflow-safe SPI timeout → ticks conversion (host + target).
 * No ESP-IDF / FreeRTOS headers.
 */

#include <stddef.h>
#include <stdint.h>

int ninlil_esp_idf_sx1262_ms_to_ticks(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks)
{
    uint64_t prod;
    uint64_t ticks;

    if (out_ticks == NULL || timeout_ms == 0u || tick_rate_hz == 0u) {
        return 0;
    }
    if (timeout_ms > UINT64_MAX / (uint64_t)tick_rate_hz) {
        return 0;
    }
    prod = (uint64_t)timeout_ms * (uint64_t)tick_rate_hz;
    ticks = prod / 1000u;
    if (prod % 1000u != 0u) {
        if (ticks == UINT64_MAX) {
            return 0;
        }
        ticks += 1u;
    }
    if (ticks == 0u) {
        ticks = 1u;
    }
    if (ticks > (uint64_t)UINT32_MAX) {
        return 0;
    }
    *out_ticks = (uint32_t)ticks;
    return 1;
}

int ninlil_esp_idf_sx1262_us_to_ticks_ceil(
    uint32_t delay_us,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks)
{
    uint64_t prod;
    uint64_t ticks;

    if (out_ticks == NULL || delay_us == 0u || tick_rate_hz == 0u) {
        return 0;
    }
    /* ticks = ceil(delay_us * tick_rate_hz / 1_000_000), min 1 */
    if (delay_us > UINT64_MAX / (uint64_t)tick_rate_hz) {
        return 0;
    }
    prod = (uint64_t)delay_us * (uint64_t)tick_rate_hz;
    ticks = prod / 1000000u;
    if (prod % 1000000u != 0u) {
        if (ticks == UINT64_MAX) {
            return 0;
        }
        ticks += 1u;
    }
    if (ticks == 0u) {
        ticks = 1u; /* never 0-tick (NRESET / delay contract) */
    }
    if (ticks > (uint64_t)UINT32_MAX) {
        return 0;
    }
    *out_ticks = (uint32_t)ticks;
    return 1;
}
