/*
 * R3 LoRa airtime calculator — integer uint64 rational, ceil-to-us.
 *
 * Algebra pin:
 *   Lora-net/sx126x_driver v2.3.2
 *   commit 9636dc4660ada4eeddf91eb7b3f7f241000bf202
 *   src/sx126x.c :: sx126x_get_lora_time_on_air_numerator / _bw_in_hz
 *
 * DO NOT use sx126x_get_lora_time_on_air_in_ms as oracle: its uint32
 * (1000*U) path overflows on legal max (wrong ms 494718 vs 34581760).
 *
 * AUTO LDRO policy: Tsym >= 16.38 ms (DS.SX1261-2.W.APP Rev 2.2 §13.4.5).
 * SF5/6: LDRO_ON accepted (ldro_effective=1) but DE unused in algebra.
 * formula_version 1 (first freeze).
 */

#include "airtime_calculator.h"

#include <string.h>

static const uint32_t k_bw_hz[NINLIL_AIRTIME_BW_COUNT] = {
    NINLIL_AIRTIME_BW_HZ_0,
    NINLIL_AIRTIME_BW_HZ_1,
    NINLIL_AIRTIME_BW_HZ_2,
    NINLIL_AIRTIME_BW_HZ_3,
    NINLIL_AIRTIME_BW_HZ_4,
    NINLIL_AIRTIME_BW_HZ_5,
    NINLIL_AIRTIME_BW_HZ_6,
    NINLIL_AIRTIME_BW_HZ_7,
    NINLIL_AIRTIME_BW_HZ_8,
    NINLIL_AIRTIME_BW_HZ_9,
};

static void zero_result(ninlil_airtime_result_t *out)
{
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
}

static int bw_is_closed(uint32_t bw_hz)
{
    size_t i;

    for (i = 0u; i < NINLIL_AIRTIME_BW_COUNT; ++i) {
        if (k_bw_hz[i] == bw_hz) {
            return 1;
        }
    }
    return 0;
}

static int ceil_div_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (b == 0u || out == NULL) {
        return 0;
    }
    *out = (a / b) + ((a % b) != 0u ? 1u : 0u);
    return 1;
}

static int mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (a == 0u || b == 0u) {
        *out = 0u;
        return 1;
    }
    if (a > (UINT64_C(0xFFFFFFFFFFFFFFFF) / b)) {
        return 0;
    }
    *out = a * b;
    return 1;
}

static int add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (a > (UINT64_C(0xFFFFFFFFFFFFFFFF) - b)) {
        return 0;
    }
    *out = a + b;
    return 1;
}

/*
 * AUTO LDRO: DE=1 iff Tsym >= 16.38 ms.
 * 2^SF * 100000 >= BW * 1638  (includes equality).
 * SEMANTIC: LDRO_AUTO_GE_16P38_MS
 *
 * SF5/6: same AUTO rule applies; closed BW set yields DE=0 in practice.
 * LDRO_ON is accepted for SF5/6 (effective=1) but SF5/6 algebra ignores DE.
 * SEMANTIC: SF56_LDRO_ON_ACCEPTED_DE_UNUSED_IN_ALGEBRA
 */
static int ldro_auto_de(uint8_t sf, uint32_t bw_hz)
{
    const uint64_t left =
        ((uint64_t)1u << (unsigned)sf) * (uint64_t)NINLIL_AIRTIME_LDRO_AUTO_NUM;
    const uint64_t right =
        (uint64_t)bw_hz * (uint64_t)NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100;

    return (left >= right) ? 1 : 0;
}

static ninlil_airtime_status_t resolve_de(
    uint8_t sf,
    uint32_t bw_hz,
    uint8_t ldro,
    uint8_t *out_de)
{
    if (out_de == NULL) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    if (ldro == NINLIL_AIRTIME_LDRO_OFF) {
        *out_de = 0u;
        return NINLIL_AIRTIME_OK;
    }
    if (ldro == NINLIL_AIRTIME_LDRO_ON) {
        /* SF5/6: accept ON; effective=1; numerator path still ignores de. */
        *out_de = 1u;
        return NINLIL_AIRTIME_OK;
    }
    if (ldro == NINLIL_AIRTIME_LDRO_AUTO) {
        *out_de = (uint8_t)ldro_auto_de(sf, bw_hz);
        return NINLIL_AIRTIME_OK;
    }
    return NINLIL_AIRTIME_INVALID_ARGUMENT;
}

/*
 * uint64 ToA numerator U (driver algebra; wider than uint32 ms wrapper).
 *
 * SEMANTIC: DRIVER_NUMERATOR_V232
 * SEMANTIC: SF56_EXPLICIT_PLUS20_IMPLICIT_PLUS0
 * SEMANTIC: SF56_EXTRA_PLUS2_SYMBOLS
 * SEMANTIC: SF7_PLUS_NUM_PLUS8
 * SEMANTIC: TOA_NUMERATOR_UINT64_EXACT
 */
static ninlil_airtime_status_t driver_toa_numerator_u64(
    uint8_t sf,
    uint8_t pl,
    uint8_t crc_on,
    uint8_t header_implicit,
    uint8_t de,
    uint8_t cr,
    uint16_t preamble,
    uint64_t *out_num,
    uint32_t *out_n_payload_symbols)
{
    int32_t ceil_numerator;
    int32_t ceil_denominator;
    int32_t cr_denom;
    int32_t ceil_term;
    int32_t intermed;
    uint64_t four_i;
    uint64_t shift;
    uint64_t product;
    uint32_t n_pay;

    if (out_num == NULL || out_n_payload_symbols == NULL) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }

    cr_denom = (int32_t)cr + 4;

    ceil_numerator = ((int32_t)pl << 3)
        + (crc_on != 0u ? 16 : 0)
        - (4 * (int32_t)sf)
        + (header_implicit != 0u ? 0 : 20);

    if (sf <= 6u) {
        /* SF5/6: DE unused in denominator (driver algebra). */
        (void)de;
        ceil_denominator = 4 * (int32_t)sf;
    } else {
        ceil_numerator += 8;
        if (de != 0u) {
            ceil_denominator = 4 * ((int32_t)sf - 2);
        } else {
            ceil_denominator = 4 * (int32_t)sf;
        }
    }

    if (ceil_denominator <= 0) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (ceil_numerator < 0) {
        ceil_numerator = 0;
    }

    ceil_term = (ceil_numerator + ceil_denominator - 1) / ceil_denominator;
    if (ceil_term < 0) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    {
        int64_t pay = 8 + (int64_t)ceil_term * (int64_t)cr_denom;
        if (pay < 0 || pay > (int64_t)UINT32_MAX) {
            return NINLIL_AIRTIME_OVERFLOW;
        }
        n_pay = (uint32_t)pay;
    }

    intermed = ceil_term * cr_denom + (int32_t)preamble + 12;
    if (sf <= 6u) {
        intermed += 2;
    }
    if (intermed < 0) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (sf < 2u) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }

    four_i = (uint64_t)(uint32_t)intermed;
    if (!mul_u64(four_i, 4u, &four_i)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (!add_u64(four_i, 1u, &four_i)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    shift = (uint64_t)1u << (unsigned)(sf - 2u);
    if (!mul_u64(four_i, shift, &product)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }

    *out_num = product;
    *out_n_payload_symbols = n_pay;
    return NINLIL_AIRTIME_OK;
}

/*
 * airtime_us = ceil(1e6 * U / BW) with uint64 intermediates.
 * SEMANTIC: AIRTIME_US_CEIL_1E6_NUM_OVER_BW
 * NOT the uint32 (1000*U) driver ms wrapper.
 */
static ninlil_airtime_status_t airtime_us_from_numerator_u64(
    uint64_t numerator,
    uint8_t sf,
    uint32_t bw_hz,
    uint32_t *out_us,
    uint32_t *out_tsym_ceil)
{
    uint64_t scaled;
    uint64_t q;
    uint64_t two_sf;
    uint64_t tsym_num;
    uint64_t tsym_q;

    if (out_us == NULL || out_tsym_ceil == NULL || bw_hz == 0u) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }

    if (!mul_u64(numerator, 1000000u, &scaled)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (!ceil_div_u64(scaled, (uint64_t)bw_hz, &q)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (q > (uint64_t)UINT32_MAX) {
        /* Legal max e.g. SF12/BW7812/... yields ~3.46e10 us > u32. */
        return NINLIL_AIRTIME_OVERFLOW;
    }
    *out_us = (uint32_t)q;

    two_sf = (uint64_t)1u << (unsigned)sf;
    if (!mul_u64(two_sf, 1000000u, &tsym_num)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (!ceil_div_u64(tsym_num, (uint64_t)bw_hz, &tsym_q)) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    if (tsym_q > (uint64_t)UINT32_MAX) {
        return NINLIL_AIRTIME_OVERFLOW;
    }
    *out_tsym_ceil = (uint32_t)tsym_q;
    return NINLIL_AIRTIME_OK;
}

ninlil_airtime_status_t ninlil_airtime_lora_us(
    const ninlil_airtime_lora_input_t *in,
    ninlil_airtime_result_t *out)
{
    ninlil_airtime_status_t st;
    uint8_t de;
    uint64_t num;
    uint32_t n_pay;
    uint32_t air_us;
    uint32_t tsym_ceil;

    if (in == NULL || out == NULL) {
        zero_result(out);
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    zero_result(out);

    if (in->reserved_zero != 0u) {
        return NINLIL_AIRTIME_STRUCT;
    }
    if (in->sf < NINLIL_AIRTIME_SF_MIN || in->sf > NINLIL_AIRTIME_SF_MAX) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    /*
     * CR must be 1..4. Long-interleaving raw codes 5..7 (DS) are NOT
     * supported by official ToA helper — explicit reject, no extrapolate.
     * SEMANTIC: CR_LONG_INTERLEAVE_5_7_REJECT
     */
    if (in->cr < NINLIL_AIRTIME_CR_MIN || in->cr > NINLIL_AIRTIME_CR_MAX) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    if (in->header_implicit != NINLIL_AIRTIME_HEADER_EXPLICIT
        && in->header_implicit != NINLIL_AIRTIME_HEADER_IMPLICIT) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    if (in->crc_on != NINLIL_AIRTIME_CRC_OFF
        && in->crc_on != NINLIL_AIRTIME_CRC_ON) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    if (in->preamble_len_symbols < NINLIL_AIRTIME_PREAMBLE_MIN) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    if (!bw_is_closed(in->bw_hz)) {
        return NINLIL_AIRTIME_UNSUPPORTED;
    }

    st = resolve_de(in->sf, in->bw_hz, in->ldro, &de);
    if (st != NINLIL_AIRTIME_OK) {
        return st;
    }

    st = driver_toa_numerator_u64(
        in->sf,
        in->payload_len_bytes,
        in->crc_on,
        in->header_implicit,
        de,
        in->cr,
        in->preamble_len_symbols,
        &num,
        &n_pay);
    if (st != NINLIL_AIRTIME_OK) {
        return st;
    }

    st = airtime_us_from_numerator_u64(
        num, in->sf, in->bw_hz, &air_us, &tsym_ceil);
    if (st != NINLIL_AIRTIME_OK) {
        return st;
    }

    out->airtime_us = air_us;
    out->n_payload_symbols = n_pay;
    out->tsym_us_ceil = tsym_ceil;
    out->toa_numerator_lo = (uint32_t)(num & 0xffffffffu);
    out->toa_numerator_hi = (uint32_t)(num >> 32);
    out->ldro_effective = de;
    out->reserved_zero[0] = 0u;
    out->reserved_zero[1] = 0u;
    out->reserved_zero[2] = 0u;
    return NINLIL_AIRTIME_OK;
}

size_t ninlil_airtime_bw_table_count(void)
{
    return NINLIL_AIRTIME_BW_COUNT;
}

ninlil_airtime_status_t ninlil_airtime_bw_table_copy(
    uint32_t *out_hz,
    size_t capacity,
    size_t *out_count)
{
    size_t i;

    if (out_count == NULL) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    *out_count = NINLIL_AIRTIME_BW_COUNT;
    if (out_hz == NULL || capacity < NINLIL_AIRTIME_BW_COUNT) {
        return NINLIL_AIRTIME_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_AIRTIME_BW_COUNT; ++i) {
        out_hz[i] = k_bw_hz[i];
    }
    return NINLIL_AIRTIME_OK;
}
