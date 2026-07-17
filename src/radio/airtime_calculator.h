#ifndef NINLIL_RADIO_AIRTIME_CALCULATOR_H
#define NINLIL_RADIO_AIRTIME_CALCULATOR_H

/*
 * R3 LoRa airtime calculator — production-private C11 API.
 *
 * Normative: docs/27-r3-airtime-calculator.md + ADR-0007.
 *
 * Algebra pin (ToA numerator / BW Hz):
 *   Lora-net/sx126x_driver v2.3.2
 *   commit 9636dc4660ada4eeddf91eb7b3f7f241000bf202
 *   src/sx126x.c :: sx126x_get_lora_time_on_air_numerator
 *                :: sx126x_get_lora_bw_in_hz
 *
 * Datasheet pin (policy / domain context, not page-level algebra substitute):
 *   DS.SX1261-2.W.APP Rev 2.2 (Dec 2024)
 *   §6.1.4 p41 ToA → driver; §6.1.1.4 p40 / §13.4.5 p90 LDRO;
 *   §13.4.5.2 p92 BW/SF/CR; §6.1.1.1 p38 SF5/6 preamble recommend 12.
 *
 * AUTO LDRO policy (R3): DE=1 iff Tsym >= 16.38 ms (rational), not formula law.
 * uint32 driver ms wrapper is NOT an oracle (overflow on legal max).
 *
 * Not public include/ninlil. Not R4/R5/RF/legal/HIL/Japan profile.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * First R3 freeze (not yet released on main). Bump only on future breaking changes.
 * LDRO AUTO Ts>=16.38ms; uint64 ToA numerator; CR 5..7 reject;
 * SF5/6: LDRO OFF/ON/AUTO accepted; DE not used in SF5/6 algebra.
 */
#define NINLIL_AIRTIME_FORMULA_VERSION ((uint32_t)1u)

#define NINLIL_AIRTIME_SF_MIN ((uint8_t)5u)
#define NINLIL_AIRTIME_SF_MAX ((uint8_t)12u)
#define NINLIL_AIRTIME_CR_MIN ((uint8_t)1u)
#define NINLIL_AIRTIME_CR_MAX ((uint8_t)4u)
#define NINLIL_AIRTIME_PREAMBLE_MIN ((uint16_t)6u)
#define NINLIL_AIRTIME_PREAMBLE_MAX ((uint16_t)65535u)
#define NINLIL_AIRTIME_PAYLOAD_MAX ((uint8_t)255u)
#define NINLIL_AIRTIME_BW_COUNT ((size_t)10u)

/* Closed BW set (Hz) — exact sx126x_get_lora_bw_in_hz mapping. */
#define NINLIL_AIRTIME_BW_HZ_0 ((uint32_t)7812u)
#define NINLIL_AIRTIME_BW_HZ_1 ((uint32_t)10417u)
#define NINLIL_AIRTIME_BW_HZ_2 ((uint32_t)15625u)
#define NINLIL_AIRTIME_BW_HZ_3 ((uint32_t)20833u)
#define NINLIL_AIRTIME_BW_HZ_4 ((uint32_t)31250u)
#define NINLIL_AIRTIME_BW_HZ_5 ((uint32_t)41667u)
#define NINLIL_AIRTIME_BW_HZ_6 ((uint32_t)62500u)
#define NINLIL_AIRTIME_BW_HZ_7 ((uint32_t)125000u)
#define NINLIL_AIRTIME_BW_HZ_8 ((uint32_t)250000u)
#define NINLIL_AIRTIME_BW_HZ_9 ((uint32_t)500000u)

/*
 * AUTO LDRO: Tsym >= 16.38 ms
 * 2^SF / BW >= 1638/100000  <=>  2^SF * 100000 >= BW * 1638
 * SEMANTIC: LDRO_AUTO_GE_16P38_MS
 */
#define NINLIL_AIRTIME_LDRO_AUTO_NUM ((uint32_t)100000u)
#define NINLIL_AIRTIME_LDRO_AUTO_DEN_MS_X100 ((uint32_t)1638u)

typedef uint32_t ninlil_airtime_status_t;

#define NINLIL_AIRTIME_OK ((ninlil_airtime_status_t)0u)
#define NINLIL_AIRTIME_INVALID_ARGUMENT ((ninlil_airtime_status_t)1u)
#define NINLIL_AIRTIME_UNSUPPORTED ((ninlil_airtime_status_t)2u)
#define NINLIL_AIRTIME_OVERFLOW ((ninlil_airtime_status_t)3u)
#define NINLIL_AIRTIME_STRUCT ((ninlil_airtime_status_t)4u)

typedef uint8_t ninlil_airtime_ldro_t;

#define NINLIL_AIRTIME_LDRO_OFF ((ninlil_airtime_ldro_t)0u)
#define NINLIL_AIRTIME_LDRO_ON ((ninlil_airtime_ldro_t)1u)
#define NINLIL_AIRTIME_LDRO_AUTO ((ninlil_airtime_ldro_t)2u)

typedef uint8_t ninlil_airtime_header_t;

#define NINLIL_AIRTIME_HEADER_EXPLICIT ((ninlil_airtime_header_t)0u)
#define NINLIL_AIRTIME_HEADER_IMPLICIT ((ninlil_airtime_header_t)1u)

typedef uint8_t ninlil_airtime_crc_t;

#define NINLIL_AIRTIME_CRC_OFF ((ninlil_airtime_crc_t)0u)
#define NINLIL_AIRTIME_CRC_ON ((ninlil_airtime_crc_t)1u)

/**
 * LoRa PHY inputs for ToA. All fields validated by ninlil_airtime_lora_us.
 * cr must be 1..4 (long-interleaving raw 0x05..0x07 → INVALID, no extrapolate).
 * reserved_zero must be 0.
 */
typedef struct ninlil_airtime_lora_input {
    uint8_t sf;                      /* 5..12 */
    uint8_t cr;                      /* 1..4 only */
    uint8_t header_implicit;         /* 0 explicit, 1 implicit */
    uint8_t crc_on;                  /* 0/1 */
    uint8_t ldro;                    /* OFF/ON/AUTO */
    uint8_t payload_len_bytes;       /* 0..255 */
    uint16_t preamble_len_symbols;   /* 6..65535 (SF5/6 recommend 12 is R5 policy) */
    uint32_t bw_hz;                  /* closed membership (driver Hz) */
    uint32_t reserved_zero;          /* must be 0 */
} ninlil_airtime_lora_input_t;

/**
 * Successful result. Failure paths zero this structure (no partial fill).
 * airtime_us is R2 per-permit max_airtime_us candidate (ceil-to-us).
 * If ceil-us exceeds UINT32_MAX → OVERFLOW (legal max can do this).
 * toa_numerator_lo/hi form uint64 driver-style U (not uint32 ms wrapper).
 */
typedef struct ninlil_airtime_result {
    uint32_t airtime_us;
    uint32_t n_payload_symbols;
    uint32_t tsym_us_ceil;
    uint32_t toa_numerator_lo; /* low 32 bits of uint64 U */
    uint32_t toa_numerator_hi; /* high 32 bits of uint64 U */
    uint8_t ldro_effective;
    uint8_t reserved_zero[3];
} ninlil_airtime_result_t;

ninlil_airtime_status_t ninlil_airtime_lora_us(
    const ninlil_airtime_lora_input_t *in,
    ninlil_airtime_result_t *out);

size_t ninlil_airtime_bw_table_count(void);

ninlil_airtime_status_t ninlil_airtime_bw_table_copy(
    uint32_t *out_hz,
    size_t capacity,
    size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_AIRTIME_CALCULATOR_H */
