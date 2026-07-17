/*
 * R3 airtime C bridge vs independent oracle (formula_version 1).
 * Host candidate — not RF/HIL/Japan complete.
 */

#include "airtime_calculator.h"
#include "airtime_r3_vectors.gen.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_eq_u32(const char *id, const char *field, uint32_t got, uint32_t exp)
{
    if (got != exp) {
        (void)fprintf(
            stderr,
            "FAIL %s %s got=%u exp=%u\n",
            id,
            field,
            (unsigned)got,
            (unsigned)exp);
        failures += 1;
    }
}

static void expect_eq_u8(const char *id, const char *field, uint8_t got, uint8_t exp)
{
    if (got != exp) {
        (void)fprintf(
            stderr,
            "FAIL %s %s got=%u exp=%u\n",
            id,
            field,
            (unsigned)got,
            (unsigned)exp);
        failures += 1;
    }
}

int main(void)
{
    size_t i;
    uint32_t bw_tbl[NINLIL_AIRTIME_BW_COUNT];
    size_t bw_n = 0u;
    ninlil_airtime_status_t st;
    static const uint32_t k_official_bw[NINLIL_AIRTIME_BW_COUNT] = {
        7812u, 10417u, 15625u, 20833u, 31250u,
        41667u, 62500u, 125000u, 250000u, 500000u,
    };

    failures = 0;

    if (NINLIL_AIRTIME_FORMULA_VERSION != NINLIL_AIRTIME_R3_ORACLE_FORMULA_VERSION
        || NINLIL_AIRTIME_FORMULA_VERSION != 1u) {
        (void)fprintf(stderr, "formula version mismatch (expect 1)\n");
        return 2;
    }

    st = ninlil_airtime_bw_table_copy(bw_tbl, NINLIL_AIRTIME_BW_COUNT, &bw_n);
    if (st != NINLIL_AIRTIME_OK || bw_n != NINLIL_AIRTIME_BW_COUNT) {
        return 3;
    }
    for (i = 0u; i < NINLIL_AIRTIME_BW_COUNT; ++i) {
        if (bw_tbl[i] != k_official_bw[i]) {
            return 3;
        }
    }

    /* CR 5..7 reject */
    {
        ninlil_airtime_lora_input_t in;
        ninlil_airtime_result_t out;
        uint8_t cr;
        (void)memset(&in, 0, sizeof(in));
        in.sf = 7u;
        in.crc_on = 1u;
        in.preamble_len_symbols = 8u;
        in.payload_len_bytes = 16u;
        in.bw_hz = 125000u;
        for (cr = 5u; cr <= 7u; ++cr) {
            in.cr = cr;
            st = ninlil_airtime_lora_us(&in, &out);
            if (st != NINLIL_AIRTIME_INVALID_ARGUMENT) {
                (void)fprintf(stderr, "cr %u must INVALID\n", (unsigned)cr);
                return 4;
            }
        }
    }

    /*
     * SF5 LDRO_OFF vs LDRO_ON: both OK, same airtime_us (17ms→16960us),
     * effective 0 vs 1. Must actually pass ON (not OFF masquerade).
     */
    {
        ninlil_airtime_lora_input_t in;
        ninlil_airtime_result_t out_off;
        ninlil_airtime_result_t out_on;
        (void)memset(&in, 0, sizeof(in));
        in.sf = 5u;
        in.cr = 1u;
        in.crc_on = 1u;
        in.payload_len_bytes = 16u;
        in.preamble_len_symbols = 12u;
        in.bw_hz = 125000u;

        in.ldro = NINLIL_AIRTIME_LDRO_OFF;
        st = ninlil_airtime_lora_us(&in, &out_off);
        if (st != NINLIL_AIRTIME_OK || out_off.airtime_us != 16960u
            || out_off.ldro_effective != 0u) {
            (void)fprintf(
                stderr,
                "sf5 OFF st=%u us=%u eff=%u\n",
                (unsigned)st,
                (unsigned)out_off.airtime_us,
                (unsigned)out_off.ldro_effective);
            return 5;
        }

        in.ldro = NINLIL_AIRTIME_LDRO_ON;
        st = ninlil_airtime_lora_us(&in, &out_on);
        if (st != NINLIL_AIRTIME_OK || out_on.airtime_us != 16960u
            || out_on.ldro_effective != 1u) {
            (void)fprintf(
                stderr,
                "sf5 ON st=%u us=%u eff=%u (must accept ON)\n",
                (unsigned)st,
                (unsigned)out_on.airtime_us,
                (unsigned)out_on.ldro_effective);
            return 6;
        }
        if (out_off.airtime_us != out_on.airtime_us) {
            (void)fprintf(stderr, "sf5 DE must not change ToA\n");
            return 7;
        }
        if (out_off.n_payload_symbols != out_on.n_payload_symbols) {
            (void)fprintf(stderr, "sf5 n_payload must match across DE\n");
            return 8;
        }
    }

    /* SF6 LDRO_ON accepted */
    {
        ninlil_airtime_lora_input_t in;
        ninlil_airtime_result_t out;
        (void)memset(&in, 0, sizeof(in));
        in.sf = 6u;
        in.cr = 1u;
        in.crc_on = 1u;
        in.ldro = NINLIL_AIRTIME_LDRO_ON;
        in.payload_len_bytes = 16u;
        in.preamble_len_symbols = 8u;
        in.bw_hz = 125000u;
        st = ninlil_airtime_lora_us(&in, &out);
        if (st != NINLIL_AIRTIME_OK || out.ldro_effective != 1u) {
            (void)fprintf(stderr, "sf6 ON must be accepted\n");
            return 9;
        }
    }

    /* Legal max OVERFLOW us */
    {
        ninlil_airtime_lora_input_t in;
        ninlil_airtime_result_t out;
        (void)memset(&in, 0, sizeof(in));
        in.sf = 12u;
        in.cr = 4u;
        in.crc_on = 1u;
        in.ldro = NINLIL_AIRTIME_LDRO_ON;
        in.payload_len_bytes = 255u;
        in.preamble_len_symbols = 65535u;
        in.bw_hz = 7812u;
        st = ninlil_airtime_lora_us(&in, &out);
        if (st != NINLIL_AIRTIME_OVERFLOW || out.airtime_us != 0u) {
            (void)fprintf(stderr, "max legal must OVERFLOW us fail-closed\n");
            return 10;
        }
    }

    /* High-value ms pins as us */
    {
        static const struct {
            uint8_t sf, cr, ih, crc, ldro, pl;
            uint16_t pre;
            uint32_t bw;
            uint32_t exp_us;
            uint8_t exp_eff;
        } hv[] = {
            {7, 1, 0, 0, 0, 0, 8, 125000u, 20736u, 0u},
            {7, 1, 0, 0, 0, 3, 8, 125000u, 25856u, 0u},
            {7, 1, 0, 0, 0, 4, 8, 125000u, 30976u, 0u},
            {7, 1, 0, 0, 0, 5, 8, 125000u, 30976u, 0u},
            {7, 1, 1, 0, 0, 5, 8, 125000u, 25856u, 0u},
            {5, 1, 0, 1, 0, 16, 12, 125000u, 16960u, 0u},
            {5, 1, 0, 1, 1, 16, 12, 125000u, 16960u, 1u},
            {6, 4, 1, 0, 0, 16, 12, 125000u, 33920u, 0u},
            {11, 1, 0, 1, 0, 16, 8, 125000u, 577536u, 0u},
            {11, 1, 0, 1, 1, 16, 8, 125000u, 659456u, 1u},
            {12, 1, 0, 1, 1, 16, 8, 250000u, 659456u, 1u},
        };
        for (i = 0u; i < sizeof(hv) / sizeof(hv[0]); ++i) {
            ninlil_airtime_lora_input_t in;
            ninlil_airtime_result_t out;
            (void)memset(&in, 0, sizeof(in));
            in.sf = hv[i].sf;
            in.cr = hv[i].cr;
            in.header_implicit = hv[i].ih;
            in.crc_on = hv[i].crc;
            in.ldro = hv[i].ldro;
            in.payload_len_bytes = hv[i].pl;
            in.preamble_len_symbols = hv[i].pre;
            in.bw_hz = hv[i].bw;
            st = ninlil_airtime_lora_us(&in, &out);
            if (st != NINLIL_AIRTIME_OK || out.airtime_us != hv[i].exp_us
                || out.ldro_effective != hv[i].exp_eff) {
                (void)fprintf(
                    stderr,
                    "hv[%u] st=%u us=%u eff=%u exp_us=%u exp_eff=%u\n",
                    (unsigned)i,
                    (unsigned)st,
                    (unsigned)out.airtime_us,
                    (unsigned)out.ldro_effective,
                    (unsigned)hv[i].exp_us,
                    (unsigned)hv[i].exp_eff);
                return 11;
            }
        }
    }

    for (i = 0u; i < (size_t)NINLIL_AIRTIME_R3_VECTOR_COUNT; ++i) {
        const ninlil_airtime_r3_vector_t *v = &ninlil_airtime_r3_vectors[i];
        ninlil_airtime_lora_input_t in;
        ninlil_airtime_result_t out;

        (void)memset(&in, 0, sizeof(in));
        (void)memset(&out, 0x5A, sizeof(out));
        in.sf = v->sf;
        in.cr = v->cr;
        in.header_implicit = v->header_implicit;
        in.crc_on = v->crc_on;
        in.ldro = v->ldro;
        in.payload_len_bytes = v->payload_len_bytes;
        in.preamble_len_symbols = v->preamble_len_symbols;
        in.bw_hz = v->bw_hz;
        in.reserved_zero = v->reserved_zero;

        st = ninlil_airtime_lora_us(&in, &out);
        expect_eq_u32(v->id, "status", (uint32_t)st, v->expect_status);
        if (v->expect_status == NINLIL_AIRTIME_OK) {
            expect_eq_u32(v->id, "airtime_us", out.airtime_us, v->expect_airtime_us);
            expect_eq_u32(
                v->id,
                "n_payload_symbols",
                out.n_payload_symbols,
                v->expect_n_payload_symbols);
            expect_eq_u32(
                v->id, "tsym_us_ceil", out.tsym_us_ceil, v->expect_tsym_us_ceil);
            expect_eq_u32(
                v->id,
                "toa_lo",
                out.toa_numerator_lo,
                v->expect_toa_numerator_lo);
            expect_eq_u32(
                v->id,
                "toa_hi",
                out.toa_numerator_hi,
                v->expect_toa_numerator_hi);
            expect_eq_u8(
                v->id,
                "ldro_effective",
                out.ldro_effective,
                v->expect_ldro_effective);
        } else {
            expect_eq_u32(v->id, "fail_airtime_zero", out.airtime_us, 0u);
        }
    }

    if (failures != 0) {
        (void)fprintf(stderr, "airtime_r3_bridge: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf(
        "airtime_r3_bridge ok: %u vectors formula_v%u\n",
        (unsigned)NINLIL_AIRTIME_R3_VECTOR_COUNT,
        (unsigned)NINLIL_AIRTIME_FORMULA_VERSION);
    return 0;
}
