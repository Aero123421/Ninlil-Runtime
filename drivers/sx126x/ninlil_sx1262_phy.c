/*
 * R9 SX1262 physical TX/RX (Proposed ADR-0025).
 * Portable C11. No heap/VLA. ESP types forbidden.
 */

#include "ninlil_sx1262_phy.h"

#include "ninlil_sx1262_cmd.h"

#include <string.h>

/* --- R9 opcodes (DS / driver; not R4 allowlist) --- */
#define CMD_SET_PACKET_TYPE ((uint8_t)0x8Au)
#define CMD_SET_RF_FREQUENCY ((uint8_t)0x86u)
#define CMD_SET_PA_CONFIG ((uint8_t)0x95u)
#define CMD_SET_TX_PARAMS ((uint8_t)0x8Eu)
#define CMD_SET_BUFFER_BASE ((uint8_t)0x8Fu)
#define CMD_SET_MODULATION_PARAMS ((uint8_t)0x8Bu)
#define CMD_SET_PACKET_PARAMS ((uint8_t)0x8Cu)
#define CMD_SET_DIO_IRQ_PARAMS ((uint8_t)0x08u)
#define CMD_GET_IRQ_STATUS ((uint8_t)0x12u)
#define CMD_CLR_IRQ_STATUS ((uint8_t)0x02u)
#define CMD_WRITE_BUFFER ((uint8_t)0x0Eu)
#define CMD_READ_BUFFER ((uint8_t)0x1Eu)
#define CMD_GET_RX_BUFFER_STATUS ((uint8_t)0x13u)
#define CMD_GET_PACKET_STATUS ((uint8_t)0x14u)
#define CMD_SET_TX ((uint8_t)0x83u)
#define CMD_SET_RX ((uint8_t)0x82u)
#define CMD_SET_STANDBY ((uint8_t)0x80u)
#define CMD_CALIBRATE_IMAGE ((uint8_t)0x98u)
#define CMD_SET_CAD_PARAMS ((uint8_t)0x88u)
#define CMD_SET_CAD ((uint8_t)0xC5u)
#define CMD_GET_STATUS ((uint8_t)0xC0u)

#define PACKET_TYPE_LORA ((uint8_t)0x01u)
#define IRQ_TX_DONE ((uint16_t)0x0001u)
#define IRQ_RX_DONE ((uint16_t)0x0002u)
#define IRQ_PREAMBLE ((uint16_t)0x0004u)
#define IRQ_HEADER_ERR ((uint16_t)0x0020u)
#define IRQ_CRC_ERR ((uint16_t)0x0040u)
#define IRQ_CAD_DONE ((uint16_t)0x0080u)
#define IRQ_CAD_DETECTED ((uint16_t)0x0100u)
#define IRQ_TIMEOUT ((uint16_t)0x0200u)

/* R3 AUTO LDRO: 2^SF * 100000 >= BW * 1638 (Tsym >= 16.38 ms). */
#define LDRO_AUTO_NUM ((uint64_t)100000ull)
#define LDRO_AUTO_DEN ((uint64_t)1638ull)

#define PHY_MAGIC ((uint32_t)0x52395358u) /* 'R9SX' */
#define SPI_CAP ((size_t)280u)

enum {
    LIFE_ZERO = 0,
    LIFE_READY = 1,
    LIFE_SHUTDOWN = 2
};

struct ninlil_sx1262_phy {
    uint32_t magic;
    uint32_t lifecycle;
    uint32_t in_flight;
    ninlil_sx1262_phy_state_t state;
    uint64_t radio_generation;
    uint64_t last_consumed_permit_seq;
    uint32_t has_consumed_seq;
    ninlil_sx1262_backend_t *backend;
    ninlil_sx1262_rf_profile_t profile;
    ninlil_sx1262_phy_irq_ops_t irq_ops;
    void *irq_ctx;
    uint64_t op_deadline_ms;
    uint16_t last_irq;
    uint8_t rx_payload[NINLIL_SX1262_PHY_MAX_FRAME];
    uint32_t rx_len;
    ninlil_sx1262_rx_meta_t rx_meta;
    uint32_t rx_pending;
    /* Sealed arm plan (immutable after arm_tx accept). */
    ninlil_sx1262_phy_tx_plan_t sealed_plan;
    uint32_t sealed_live;
    uint8_t ant_sw_active;
    ninlil_sx1262_phy_stats_t stats;
    ninlil_sx1262_error_t last_error;
    uint8_t spi_tx[SPI_CAP];
    uint8_t spi_rx[SPI_CAP];
};

_Static_assert(
    sizeof(struct ninlil_sx1262_phy) <= NINLIL_SX1262_PHY_OBJECT_BYTES,
    "phy object size");
_Static_assert(
    _Alignof(struct ninlil_sx1262_phy) >= NINLIL_SX1262_PHY_OBJECT_ALIGN,
    "phy align");

static void clear_err(ninlil_sx1262_error_t *e)
{
    if (e != NULL) {
        (void)memset(e, 0, sizeof(*e));
    }
}

static void set_err(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out,
    ninlil_sx1262_status_t st,
    ninlil_sx1262_stage_t stage,
    ninlil_sx1262_reason_t reason,
    const char *hint)
{
    ninlil_sx1262_error_t local;
    size_t i;

    clear_err(&local);
    local.status = st;
    local.stage = stage;
    local.reason = reason;
    if (hint != NULL) {
        for (i = 0u; i + 1u < NINLIL_SX1262_HINT_BYTES && hint[i] != '\0'; ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (phy != NULL) {
        phy->last_error = local;
    }
    if (out != NULL) {
        *out = local;
    }
}

static void sat_inc(uint64_t *c)
{
    if (c != NULL && *c < UINT64_MAX) {
        *c += 1u;
    }
}

static int header_ok(uint16_t ver, uint16_t size, size_t need)
{
    return ver == NINLIL_SX1262_PHY_ABI_VERSION && (size_t)size >= need;
}

int ninlil_sx1262_phy_ldro_auto_effective(uint8_t sf, uint32_t bw_hz)
{
    uint64_t left;
    uint64_t right;

    if (sf < 5u || sf > 12u || bw_hz == 0u) {
        return 0;
    }
    left = ((uint64_t)1u << (unsigned)sf) * LDRO_AUTO_NUM;
    right = (uint64_t)bw_hz * LDRO_AUTO_DEN;
    return (left >= right) ? 1 : 0;
}

int ninlil_sx1262_rf_freq_to_reg(uint32_t freq_hz, uint32_t *out_reg)
{
    uint64_t num;
    uint64_t den = 32000000ull;
    uint64_t reg;

    if (out_reg == NULL || freq_hz == 0u) {
        return 0;
    }
    /* reg = freq_hz * 2^25 / 32e6 */
    num = (uint64_t)freq_hz * 33554432ull;
    reg = num / den;
    if (reg > 0xFFFFFFFFull) {
        return 0;
    }
    *out_reg = (uint32_t)reg;
    return 1;
}

int ninlil_sx1262_compose_pa_tx_params(
    int32_t power_mdb,
    uint8_t *out_pa_duty,
    uint8_t *out_hp_max,
    uint8_t *out_device_sel,
    uint8_t *out_pa_lut,
    int8_t *out_power_dbm,
    uint8_t *out_ramp)
{
    int32_t dbm;

    if (out_pa_duty == NULL || out_hp_max == NULL || out_device_sel == NULL
        || out_pa_lut == NULL || out_power_dbm == NULL || out_ramp == NULL) {
        return 0;
    }
    dbm = power_mdb / 1000;
    if (dbm < -9) {
        dbm = -9;
    }
    if (dbm > 22) {
        dbm = 22;
    }
    /* SX1262 HP PA path defaults (driver-style closed composition). */
    *out_pa_duty = 0x04u;
    *out_hp_max = 0x07u;
    *out_device_sel = 0x00u;
    *out_pa_lut = 0x01u;
    *out_power_dbm = (int8_t)dbm;
    *out_ramp = 0x04u; /* 200 µs ramp */
    return 1;
}

void ninlil_sx1262_rf_profile_lab_default(ninlil_sx1262_rf_profile_t *out)
{
    if (out == NULL) {
        return;
    }
    (void)memset(out, 0, sizeof(*out));
    out->abi_version = NINLIL_SX1262_PHY_ABI_VERSION;
    out->struct_size = (uint16_t)sizeof(*out);
    /* LAB fixture band only — not Japan production legal table. */
    out->freq_hz_min = 902000000u;
    out->freq_hz_max = 928000000u;
    out->bandwidth_hz = 125000u;
    out->sf_min = 7u;
    out->sf_max = 12u;
    out->cr_denom_min = 5u;
    out->cr_denom_max = 8u;
    out->preamble_min = 8u;
    out->preamble_max = 16u;
    out->tx_power_mdb_min = 0;
    out->tx_power_mdb_max = 14000;
    out->max_airtime_us_ceiling = 2000000u;
}

size_t ninlil_sx1262_phy_object_size(void)
{
    return sizeof(struct ninlil_sx1262_phy);
}

size_t ninlil_sx1262_phy_object_align(void)
{
    return NINLIL_SX1262_PHY_OBJECT_ALIGN;
}

static ninlil_sx1262_status_t wait_busy(
    ninlil_sx1262_phy_t *phy,
    uint32_t timeout_ms,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_backend_t *be = phy->backend;
    uint64_t start;
    uint64_t now;
    uint64_t max_polls;
    uint64_t polls;
    int high;

    if (!ninlil_sx1262_calc_busy_max_polls(
            timeout_ms,
            be->board.busy_poll_interval_us,
            be->board.busy_poll_slack,
            &max_polls)) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_OVERFLOW,
            "polls");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (be->bus_ops.now_ms(be->bus_ctx, &start) != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
            "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    for (polls = 0u; polls < max_polls; ++polls) {
        high = 1;
        if (be->bus_ops.busy_is_high(be->bus_ctx, &high) != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "busy");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (high == 0) {
            return NINLIL_SX1262_OK;
        }
        if (be->bus_ops.now_ms(be->bus_ctx, &now) != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "now2");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (ninlil_sx1262_busy_deadline_reached(start, now, timeout_ms) != 0) {
            sat_inc(&phy->stats.busy_stuck);
            set_err(phy, out_error, NINLIL_SX1262_BUSY_TIMEOUT,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_BUSY_STUCK,
                "BUSY stuck");
            phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
            return NINLIL_SX1262_BUSY_TIMEOUT;
        }
        if (be->bus_ops.delay_us(be->bus_ctx, be->board.busy_poll_interval_us)
            != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "delay");
            return NINLIL_SX1262_BUS_ERROR;
        }
    }
    sat_inc(&phy->stats.busy_stuck);
    set_err(phy, out_error, NINLIL_SX1262_BUSY_TIMEOUT,
        NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_BUSY_STUCK,
        "poll cap");
    phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
    return NINLIL_SX1262_BUSY_TIMEOUT;
}

static ninlil_sx1262_status_t spi_xfer_raw(
    ninlil_sx1262_phy_t *phy,
    size_t len,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_backend_t *be = phy->backend;
    ninlil_sx1262_status_t st;

    if (len == 0u || len > SPI_CAP) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_NULL_ARG, "len");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    st = wait_busy(phy, be->board.spi_busy_timeout_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if (be->bus_ops.spi_transfer(be->bus_ctx, phy->spi_tx, phy->spi_rx, len)
        != 0) {
        set_err(phy, out_error, NINLIL_SX1262_SPI_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL, "spi");
        return NINLIL_SX1262_SPI_ERROR;
    }
    sat_inc(&be->stats.spi_xfers);
    if (be->bus_ops.delay_us(be->bus_ctx, be->board.post_spi_busy_guard_us)
        != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL, "guard");
        return NINLIL_SX1262_BUS_ERROR;
    }
    return wait_busy(phy, be->board.spi_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t get_status_check(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint8_t cmd_st;

    phy->spi_tx[0] = CMD_GET_STATUS;
    phy->spi_tx[1] = 0u;
    st = spi_xfer_raw(phy, 2u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    cmd_st = ninlil_sx1262_status_cmd_status(phy->spi_rx[1]);
    if (ninlil_sx1262_cmd_status_is_fail(cmd_st)) {
        sat_inc(&phy->stats.status_reject);
        set_err(phy, out_error, NINLIL_SX1262_STATUS_INVALID,
            NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
            "GetStatus fail");
        return NINLIL_SX1262_STATUS_INVALID;
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t spi_xfer(
    ninlil_sx1262_phy_t *phy,
    size_t len,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint8_t status_b;
    uint8_t cmd_st;
    uint8_t opcode;

    opcode = phy->spi_tx[0];
    st = spi_xfer_raw(phy, len, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /*
     * DS Table 10-1 / 13-85: validate every command status after BUSY.
     * len>=2: use rx[1]. 1-byte cmds (e.g. SetCad 0xC5): follow-up GetStatus.
     */
    if (len >= 2u && opcode != CMD_GET_STATUS) {
        status_b = phy->spi_rx[1];
        cmd_st = ninlil_sx1262_status_cmd_status(status_b);
        if (ninlil_sx1262_cmd_status_is_fail(cmd_st)) {
            sat_inc(&phy->stats.status_reject);
            set_err(phy, out_error, NINLIL_SX1262_STATUS_INVALID,
                NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
                "cmd_status fail");
            return NINLIL_SX1262_STATUS_INVALID;
        }
    } else if (len < 2u) {
        st = get_status_check(phy, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
    } else if (opcode == CMD_GET_STATUS) {
        cmd_st = ninlil_sx1262_status_cmd_status(phy->spi_rx[1]);
        if (ninlil_sx1262_cmd_status_is_fail(cmd_st)) {
            sat_inc(&phy->stats.status_reject);
            set_err(phy, out_error, NINLIL_SX1262_STATUS_INVALID,
                NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
                "GetStatus fail");
            return NINLIL_SX1262_STATUS_INVALID;
        }
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t ant_sw_set(
    ninlil_sx1262_phy_t *phy,
    int active,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_backend_t *be = phy->backend;

    if ((be->board.feature_flags & NINLIL_SX1262_FEATURE_ANT_SW_PRESENT) == 0u
        || be->bus_ops.ant_sw_set == NULL) {
        return NINLIL_SX1262_OK;
    }
    if (be->bus_ops.ant_sw_set(be->bus_ctx, active) != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL, "ant_sw");
        return NINLIL_SX1262_BUS_ERROR;
    }
    phy->ant_sw_active = active != 0 ? 1u : 0u;
    if (active != 0) {
        if (phy->state == NINLIL_SX1262_PHY_STATE_RX_ACTIVE
            || phy->state == NINLIL_SX1262_PHY_STATE_CONFIGURING) {
            /* counted by caller for tx/rx */
        }
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t cmd1(
    ninlil_sx1262_phy_t *phy,
    uint8_t op,
    uint8_t p0,
    ninlil_sx1262_error_t *out_error)
{
    phy->spi_tx[0] = op;
    phy->spi_tx[1] = p0;
    return spi_xfer(phy, 2u, out_error);
}

static ninlil_sx1262_status_t cmd_n(
    ninlil_sx1262_phy_t *phy,
    const uint8_t *bytes,
    size_t len,
    ninlil_sx1262_error_t *out_error)
{
    size_t i;

    if (len > SPI_CAP) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_NULL_ARG, "cmdn");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    for (i = 0u; i < len; ++i) {
        phy->spi_tx[i] = bytes[i];
    }
    return spi_xfer(phy, len, out_error);
}

static ninlil_sx1262_status_t set_standby_rc(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    return cmd1(phy, CMD_SET_STANDBY, NINLIL_SX1262_STANDBY_CFG_RC, out_error);
}

static ninlil_sx1262_status_t clear_irq_all(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t f[3];
    ninlil_sx1262_status_t st;
    uint16_t irq = 0u;

    f[0] = CMD_CLR_IRQ_STATUS;
    f[1] = 0xFFu;
    f[2] = 0xFFu;
    st = cmd_n(phy, f, 3u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* Fail closed if IRQ bits remain after clear. */
    phy->spi_tx[0] = CMD_GET_IRQ_STATUS;
    phy->spi_tx[1] = 0u;
    phy->spi_tx[2] = 0u;
    phy->spi_tx[3] = 0u;
    st = spi_xfer(phy, 4u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    irq = (uint16_t)(((uint16_t)phy->spi_rx[2] << 8) | phy->spi_rx[3]);
    if (irq != 0u) {
        sat_inc(&phy->stats.status_reject);
        set_err(phy, out_error, NINLIL_SX1262_DEVICE_ERROR,
            NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_DEVICE_ERRORS,
            "IRQ clear residual");
        return NINLIL_SX1262_DEVICE_ERROR;
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t get_irq(
    ninlil_sx1262_phy_t *phy,
    uint16_t *out_irq,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;

    phy->spi_tx[0] = CMD_GET_IRQ_STATUS;
    phy->spi_tx[1] = 0u;
    phy->spi_tx[2] = 0u;
    phy->spi_tx[3] = 0u;
    st = spi_xfer(phy, 4u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* byte0 RFU, byte1 status, byte2..3 irq (driver layout). */
    *out_irq = (uint16_t)(((uint16_t)phy->spi_rx[2] << 8) | phy->spi_rx[3]);
    phy->last_irq = *out_irq;
    return NINLIL_SX1262_OK;
}

static int profile_ok(const ninlil_sx1262_rf_profile_t *p)
{
    return p != NULL
        && header_ok(p->abi_version, p->struct_size, sizeof(*p))
        && p->reserved_zero == 0u
        && p->freq_hz_min > 0u
        && p->freq_hz_max >= p->freq_hz_min
        && p->bandwidth_hz > 0u
        && p->sf_min >= 5u
        && p->sf_max <= 12u
        && p->sf_max >= p->sf_min
        && p->cr_denom_min >= 5u
        && p->cr_denom_max <= 8u
        && p->cr_denom_max >= p->cr_denom_min
        && p->preamble_max >= p->preamble_min
        && p->preamble_min > 0u
        && p->tx_power_mdb_max >= p->tx_power_mdb_min
        && p->max_airtime_us_ceiling > 0u;
}

#if !defined(NINLIL_SX1262_PRODUCTION_BUILD)
static int permit_matches_profile(
    const ninlil_sx1262_tx_permit_t *permit,
    const ninlil_sx1262_rf_profile_t *prof)
{
    return permit->frequency_hz >= prof->freq_hz_min
        && permit->frequency_hz <= prof->freq_hz_max
        && permit->bandwidth_hz == prof->bandwidth_hz
        && permit->spreading_factor >= prof->sf_min
        && permit->spreading_factor <= prof->sf_max
        && permit->coding_rate_denom >= prof->cr_denom_min
        && permit->coding_rate_denom <= prof->cr_denom_max
        && permit->preamble_symbols >= prof->preamble_min
        && permit->preamble_symbols <= prof->preamble_max
        && permit->tx_power_mdb >= prof->tx_power_mdb_min
        && permit->tx_power_mdb <= prof->tx_power_mdb_max
        && permit->max_airtime_us > 0u
        && permit->max_airtime_us <= prof->max_airtime_us_ceiling;
}

static int digest_any(const uint8_t *d)
{
    size_t i;

    for (i = 0u; i < NINLIL_SX1262_PHY_DIGEST_BYTES; ++i) {
        if (d[i] != 0u) {
            return 1;
        }
    }
    return 0;
}
#endif /* !NINLIL_SX1262_PRODUCTION_BUILD */

static ninlil_sx1262_status_t configure_lora(
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_tx_permit_t *permit,
    const uint8_t *frame,
    uint32_t frame_len,
    int for_tx,
    uint8_t ldro_effective,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint32_t freq_reg;
    uint8_t f[16];
    uint8_t pa_duty;
    uint8_t hp_max;
    uint8_t dev_sel;
    uint8_t pa_lut;
    int8_t pwr;
    uint8_t ramp;
    uint32_t i;
    uint8_t bw_code;
    uint8_t cr_code;
    uint8_t ldro_bit;

    st = set_standby_rc(phy, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    st = cmd1(phy, CMD_SET_PACKET_TYPE, PACKET_TYPE_LORA, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if (!ninlil_sx1262_rf_freq_to_reg(permit->frequency_hz, &freq_reg)) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "freq");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    f[0] = CMD_SET_RF_FREQUENCY;
    f[1] = (uint8_t)((freq_reg >> 24) & 0xffu);
    f[2] = (uint8_t)((freq_reg >> 16) & 0xffu);
    f[3] = (uint8_t)((freq_reg >> 8) & 0xffu);
    f[4] = (uint8_t)(freq_reg & 0xffu);
    st = cmd_n(phy, f, 5u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* Image cal for sub-GHz LAB band (closed table entry). */
    f[0] = CMD_CALIBRATE_IMAGE;
    f[1] = 0xE1u;
    f[2] = 0xE9u;
    st = cmd_n(phy, f, 3u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if (!ninlil_sx1262_compose_pa_tx_params(
            permit->tx_power_mdb,
            &pa_duty,
            &hp_max,
            &dev_sel,
            &pa_lut,
            &pwr,
            &ramp)) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "pa");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    f[0] = CMD_SET_PA_CONFIG;
    f[1] = pa_duty;
    f[2] = hp_max;
    f[3] = dev_sel;
    f[4] = pa_lut;
    st = cmd_n(phy, f, 5u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    f[0] = CMD_SET_TX_PARAMS;
    f[1] = (uint8_t)pwr;
    f[2] = ramp;
    st = cmd_n(phy, f, 3u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    f[0] = CMD_SET_BUFFER_BASE;
    f[1] = 0x00u;
    f[2] = 0x00u;
    st = cmd_n(phy, f, 3u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* BW 125 kHz → 0x04 (driver SX126X_LORA_BW_125). */
    bw_code = 0x04u;
    if (permit->bandwidth_hz == 250000u) {
        bw_code = 0x05u;
    } else if (permit->bandwidth_hz == 500000u) {
        bw_code = 0x06u;
    }
    cr_code = (uint8_t)(permit->coding_rate_denom - 4u); /* 5..8 → 1..4 */
    ldro_bit = (ldro_effective != 0u) ? 0x01u : 0x00u;
    f[0] = CMD_SET_MODULATION_PARAMS;
    f[1] = permit->spreading_factor;
    f[2] = bw_code;
    f[3] = cr_code;
    f[4] = ldro_bit; /* LDRO / DE bit (R3 AUTO result when sealed) */
    st = cmd_n(phy, f, 5u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    f[0] = CMD_SET_PACKET_PARAMS;
    f[1] = (uint8_t)((permit->preamble_symbols >> 8) & 0xffu);
    f[2] = (uint8_t)(permit->preamble_symbols & 0xffu);
    f[3] = 0x00u; /* explicit header */
    /* In explicit-header RX, configure the full variable-length ceiling.
     * TX still seals the exact payload length into PacketParams. */
    f[4] = for_tx != 0
        ? (uint8_t)frame_len
        : (uint8_t)NINLIL_SX1262_PHY_MAX_FRAME;
    f[5] = 0x01u; /* CRC on */
    f[6] = 0x00u; /* standard IQ */
    st = cmd_n(phy, f, 7u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    f[0] = CMD_SET_DIO_IRQ_PARAMS;
    f[1] = 0xFFu;
    f[2] = 0xFFu; /* IRQ mask all */
    /* DIO1: TxDone|RxDone|Timeout|CadDone|CadDetected|CRC|Header */
    f[3] = 0x03u; /* high: CadDetected|Timeout bits 8..9 family */
    f[4] = 0xE3u; /* low: TxDone|RxDone|CadDone|Header|CRC */
    f[5] = 0x00u;
    f[6] = 0x00u;
    f[7] = 0x00u;
    f[8] = 0x00u;
    st = cmd_n(phy, f, 9u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if (for_tx != 0 && frame != NULL && frame_len > 0u) {
        if ((size_t)frame_len + 2u > SPI_CAP) {
            set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_NULL_ARG,
                "frame");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
        phy->spi_tx[0] = CMD_WRITE_BUFFER;
        phy->spi_tx[1] = 0x00u;
        for (i = 0u; i < frame_len; ++i) {
            phy->spi_tx[2u + i] = frame[i];
        }
        st = spi_xfer(phy, (size_t)frame_len + 2u, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
    }
    st = clear_irq_all(phy, out_error);
    return st;
}

ninlil_sx1262_status_t ninlil_sx1262_phy_init(
    ninlil_sx1262_phy_object_t *object,
    ninlil_sx1262_backend_t *backend,
    const ninlil_sx1262_rf_profile_t *profile,
    const ninlil_sx1262_phy_irq_ops_t *irq_ops,
    void *irq_ctx,
    ninlil_sx1262_phy_t **out_phy,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_phy_t *phy;

    if (object == NULL || backend == NULL || profile == NULL
        || out_phy == NULL) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (backend->magic != NINLIL_SX1262_MAGIC || backend->lifecycle != 2u) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NOT_READY,
            "backend");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (!profile_ok(profile)) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
            "profile");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (sizeof(struct ninlil_sx1262_phy) > sizeof(object->storage)) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_OVERFLOW,
            "objsize");
        return NINLIL_SX1262_INVALID_STATE;
    }
    phy = (ninlil_sx1262_phy_t *)(void *)object->storage;
    if (phy->magic != 0u || phy->lifecycle != 0u) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NOT_FRESH,
            "fresh");
        return NINLIL_SX1262_INVALID_STATE;
    }
    (void)memset(object->storage, 0, sizeof(object->storage));
    phy = (ninlil_sx1262_phy_t *)(void *)object->storage;
    phy->magic = PHY_MAGIC;
    phy->lifecycle = LIFE_READY;
    phy->backend = backend;
    phy->profile = *profile;
    if (irq_ops != NULL) {
        phy->irq_ops = *irq_ops;
    }
    phy->irq_ctx = irq_ctx;
    phy->radio_generation = 1u;
    phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
    *out_phy = phy;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}

uint64_t ninlil_sx1262_phy_generation(const ninlil_sx1262_phy_t *phy)
{
    return phy == NULL ? 0u : phy->radio_generation;
}

ninlil_sx1262_phy_state_t ninlil_sx1262_phy_state(const ninlil_sx1262_phy_t *phy)
{
    return phy == NULL ? NINLIL_SX1262_PHY_STATE_FAULT : phy->state;
}

static ninlil_sx1262_status_t run_lbt_cad(
    ninlil_sx1262_phy_t *phy,
    uint32_t timeout_ms,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint64_t start;
    uint64_t now;
    uint16_t irq = 0u;
    uint8_t f[8];
    uint32_t polls;

    if (timeout_ms == 0u) {
        timeout_ms = 50u;
    }
    /* Closed LAB CAD params (not Japan legal timing table). */
    f[0] = CMD_SET_CAD_PARAMS;
    f[1] = 0x02u; /* cadSymbolNum = 2 */
    f[2] = 22u;   /* cadDetPeak */
    f[3] = 10u;   /* cadDetMin */
    f[4] = 0x00u; /* CAD_ONLY exit */
    f[5] = 0x00u;
    f[6] = 0x00u;
    f[7] = 0x40u; /* short timeout steps */
    st = cmd_n(phy, f, 8u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    st = clear_irq_all(phy, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    f[0] = CMD_SET_CAD;
    st = cmd_n(phy, f, 1u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &start) != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL, "lbt now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    for (polls = 0u; polls < 256u; ++polls) {
        st = get_irq(phy, &irq, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
        if ((irq & IRQ_CAD_DONE) != 0u) {
            (void)clear_irq_all(phy, out_error);
            if ((irq & IRQ_CAD_DETECTED) != 0u) {
                sat_inc(&phy->stats.lbt_busy);
                set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
                    NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
                    "LBT busy");
                return NINLIL_SX1262_TX_DENIED;
            }
            sat_inc(&phy->stats.lbt_clear);
            return NINLIL_SX1262_OK;
        }
        if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL,
                "lbt now2");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (now >= start + timeout_ms) {
            sat_inc(&phy->stats.lbt_timeout);
            set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
                NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
                "LBT deadline");
            return NINLIL_SX1262_TX_DENIED;
        }
        if (phy->backend->bus_ops.delay_us(
                phy->backend->bus_ctx, phy->backend->board.busy_poll_interval_us)
            != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL,
                "lbt delay");
            return NINLIL_SX1262_BUS_ERROR;
        }
    }
    sat_inc(&phy->stats.lbt_timeout);
    set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
        NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
        "LBT poll cap");
    return NINLIL_SX1262_TX_DENIED;
}

/*
 * Sole SetTx issuer. Production callers: R9 edge after R1 HAL only.
 * Seals plan fields at entry; payload/context cannot change after seal.
 */
ninlil_sx1262_status_t ninlil_sx1262_phy_arm_tx(
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_phy_tx_plan_t *plan,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_tx_permit_t synth;
    ninlil_sx1262_status_t st;
    uint64_t now;
    uint8_t f[4];
    uint8_t ldro;
    size_t i;

    if (phy == NULL || plan == NULL || frame == NULL || frame_len == 0u
        || frame_len > NINLIL_SX1262_PHY_MAX_FRAME) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NULL_ARG, "arm");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (phy->magic != PHY_MAGIC || phy->lifecycle != LIFE_READY) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NOT_READY, "arm");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (plan->expected_radio_generation != phy->radio_generation) {
        sat_inc(&phy->stats.stale_gen_reject);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "stale gen");
        return NINLIL_SX1262_TX_DENIED;
    }
    if (plan->settx_timeout_steps == 0u
        || plan->settx_timeout_steps > 0xFFFFFFu) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_OVERFLOW,
            "timeout steps");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    /* Seal: frame length must match plan (no post-permit substitution). */
    if (plan->frame_byte_length != 0u && plan->frame_byte_length != frame_len) {
        sat_inc(&phy->stats.seal_reject);
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "seal frame_len");
        return NINLIL_SX1262_TX_DENIED;
    }
    /* Profile bounds (R2/R5 numbers already bound into phy profile). */
    if (plan->frequency_hz < phy->profile.freq_hz_min
        || plan->frequency_hz > phy->profile.freq_hz_max
        || plan->bandwidth_hz != phy->profile.bandwidth_hz
        || plan->spreading_factor < phy->profile.sf_min
        || plan->spreading_factor > phy->profile.sf_max
        || plan->coding_rate_denom < phy->profile.cr_denom_min
        || plan->coding_rate_denom > phy->profile.cr_denom_max
        || plan->preamble_symbols < phy->profile.preamble_min
        || plan->preamble_symbols > phy->profile.preamble_max
        || plan->tx_power_mdb < phy->profile.tx_power_mdb_min
        || plan->tx_power_mdb > phy->profile.tx_power_mdb_max) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "profile bounds");
        return NINLIL_SX1262_TX_DENIED;
    }
    if (phy->in_flight != 0u
        || (phy->state != NINLIL_SX1262_PHY_STATE_IDLE
            && phy->state != NINLIL_SX1262_PHY_STATE_RX_ACTIVE)) {
        set_err(phy, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "arm");
        return NINLIL_SX1262_BUSY;
    }

    /* Seal plan before any RF command (immutable after this point). */
    phy->sealed_plan = *plan;
    if (phy->sealed_plan.frame_byte_length == 0u) {
        phy->sealed_plan.frame_byte_length = frame_len;
    }
    phy->sealed_live = 1u;

    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
        phy->sealed_live = 0u;
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL, "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (phy->sealed_plan.permit_sequence != 0u
        && phy->sealed_plan.expiry_ms != 0u
        && (now < phy->sealed_plan.not_before_ms
            || now >= phy->sealed_plan.expiry_ms)) {
        sat_inc(&phy->stats.seal_reject);
        sat_inc(&phy->stats.tx_deny);
        phy->sealed_live = 0u;
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "seal window");
        return NINLIL_SX1262_TX_DENIED;
    }

    ldro = phy->sealed_plan.ldro_effective;
    if (phy->sealed_plan.permit_sequence != 0u
        || phy->sealed_plan.ldro_effective > 1u) {
        /* Prefer sealed AUTO result; clamp invalid. */
        if (ldro > 1u) {
            ldro = (uint8_t)ninlil_sx1262_phy_ldro_auto_effective(
                phy->sealed_plan.spreading_factor, phy->sealed_plan.bandwidth_hz);
        }
    } else {
        ldro = (uint8_t)ninlil_sx1262_phy_ldro_auto_effective(
            phy->sealed_plan.spreading_factor, phy->sealed_plan.bandwidth_hz);
    }

    (void)memset(&synth, 0, sizeof(synth));
    synth.frequency_hz = phy->sealed_plan.frequency_hz;
    synth.bandwidth_hz = phy->sealed_plan.bandwidth_hz;
    synth.spreading_factor = phy->sealed_plan.spreading_factor;
    synth.coding_rate_denom = phy->sealed_plan.coding_rate_denom;
    synth.preamble_symbols = phy->sealed_plan.preamble_symbols;
    synth.tx_power_mdb = phy->sealed_plan.tx_power_mdb;
    synth.max_airtime_us =
        phy->sealed_plan.max_airtime_us != 0u ? phy->sealed_plan.max_airtime_us
                                              : 1u;
    synth.frame_byte_length = phy->sealed_plan.frame_byte_length;
    for (i = 0u; i < NINLIL_SX1262_PHY_DIGEST_BYTES; ++i) {
        synth.frame_digest[i] = phy->sealed_plan.frame_digest[i];
    }

    sat_inc(&phy->stats.tx_attempts);
    phy->in_flight = 1u;
    phy->state = NINLIL_SX1262_PHY_STATE_CONFIGURING;
    st = configure_lora(phy, &synth, frame, frame_len, 1, ldro, out_error);
    if (st != NINLIL_SX1262_OK) {
        phy->in_flight = 0u;
        phy->sealed_live = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        sat_inc(&phy->stats.tx_deny);
        return st;
    }
    st = ant_sw_set(phy, 1, out_error);
    if (st != NINLIL_SX1262_OK) {
        phy->in_flight = 0u;
        phy->sealed_live = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        sat_inc(&phy->stats.tx_deny);
        return st;
    }
    sat_inc(&phy->stats.ant_sw_tx);

    if (phy->sealed_plan.require_lbt != 0u) {
        st = run_lbt_cad(phy, phy->sealed_plan.lbt_timeout_ms, out_error);
        if (st != NINLIL_SX1262_OK) {
            (void)ant_sw_set(phy, 0, NULL);
            phy->in_flight = 0u;
            phy->sealed_live = 0u;
            phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
            sat_inc(&phy->stats.tx_deny);
            return st;
        }
    }

    /* Sole SetTx site: timeout already converted by R9 edge (RTC 15.625µs). */
    f[0] = CMD_SET_TX;
    f[1] = (uint8_t)((phy->sealed_plan.settx_timeout_steps >> 16) & 0xffu);
    f[2] = (uint8_t)((phy->sealed_plan.settx_timeout_steps >> 8) & 0xffu);
    f[3] = (uint8_t)(phy->sealed_plan.settx_timeout_steps & 0xffu);
    st = cmd_n(phy, f, 4u, out_error);
    if (st != NINLIL_SX1262_OK) {
        (void)ant_sw_set(phy, 0, NULL);
        phy->in_flight = 0u;
        phy->sealed_live = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        sat_inc(&phy->stats.tx_deny);
        return st;
    }
    sat_inc(&phy->stats.settx_commands);
    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
        (void)ant_sw_set(phy, 0, NULL);
        phy->in_flight = 0u;
        phy->sealed_live = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL, "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    /* Host deadline: steps * 15.625µs ≈ steps * 1000/64 µs → ms + margin. */
    phy->op_deadline_ms =
        now + (phy->sealed_plan.settx_timeout_steps / 64u) + 50u;
    phy->state = NINLIL_SX1262_PHY_STATE_TX_ACTIVE;
    phy->in_flight = 0u;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}

#if !defined(NINLIL_SX1262_PRODUCTION_BUILD)
/*
 * Fixture-only wrapper. Production composition MUST use
 * ninlil_radio_hal_transmit_with_permit → R9 edge → phy_arm_tx.
 * Converts legacy permit fields to a plan and issues SetTx only via arm_tx.
 * Not linked under NINLIL_SX1262_PRODUCTION_BUILD (ESP/HIL).
 */
ninlil_sx1262_status_t ninlil_sx1262_request_transmit_with_permit(
    ninlil_sx1262_phy_t *phy,
    const ninlil_sx1262_tx_permit_t *permit,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_phy_tx_plan_t plan;
    ninlil_sx1262_status_t st;
    uint64_t now;
    uint64_t us;
    uint64_t steps;
    size_t i;

    if (phy == NULL || permit == NULL || frame == NULL) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (phy->magic != PHY_MAGIC || phy->lifecycle != LIFE_READY) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NOT_READY,
            "life");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (!header_ok(
            permit->abi_version, permit->struct_size, sizeof(*permit))
        || permit->reserved_zero != 0u
        || permit->permit_sequence == 0u
        || permit->attempt_id == 0u
        || frame_len == 0u
        || frame_len > NINLIL_SX1262_PHY_MAX_FRAME
        || permit->frame_byte_length != frame_len
        || !digest_any(permit->frame_digest)) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NULL_ARG,
            "permit shape");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (permit->radio_generation != phy->radio_generation) {
        sat_inc(&phy->stats.stale_gen_reject);
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "stale generation");
        return NINLIL_SX1262_TX_DENIED;
    }
    if (phy->has_consumed_seq != 0u
        && permit->permit_sequence <= phy->last_consumed_permit_seq) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "permit replay");
        return NINLIL_SX1262_TX_DENIED;
    }
    if (!permit_matches_profile(permit, &phy->profile)) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "profile bounds");
        return NINLIL_SX1262_TX_DENIED;
    }
    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_SPI_FAIL, "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (now < permit->not_before_ms || now >= permit->expiry_ms
        || permit->expiry_ms <= permit->not_before_ms) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_TX_DENIED,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
            "expiry");
        return NINLIL_SX1262_TX_DENIED;
    }

    us = (uint64_t)permit->max_airtime_us + 50000ull;
    steps = (us * 64ull + 999ull) / 1000ull;
    if (steps == 0u) {
        steps = 1u;
    }
    if (steps > 0xFFFFFFull) {
        sat_inc(&phy->stats.tx_deny);
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_OVERFLOW,
            "SetTx timeout");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    (void)memset(&plan, 0, sizeof(plan));
    plan.frequency_hz = permit->frequency_hz;
    plan.bandwidth_hz = permit->bandwidth_hz;
    plan.spreading_factor = permit->spreading_factor;
    plan.coding_rate_denom = permit->coding_rate_denom;
    plan.preamble_symbols = permit->preamble_symbols;
    plan.tx_power_mdb = permit->tx_power_mdb;
    plan.settx_timeout_steps = (uint32_t)steps;
    plan.expected_radio_generation = phy->radio_generation;

    plan.frame_byte_length = frame_len;
    for (i = 0u; i < NINLIL_SX1262_PHY_DIGEST_BYTES; ++i) {
        plan.frame_digest[i] = permit->frame_digest[i];
    }
    plan.max_airtime_us = permit->max_airtime_us;
    plan.not_before_ms = permit->not_before_ms;
    plan.expiry_ms = permit->expiry_ms;
    plan.permit_sequence = permit->permit_sequence;
    plan.ldro_effective = (uint8_t)ninlil_sx1262_phy_ldro_auto_effective(
        permit->spreading_factor, permit->bandwidth_hz);
    plan.require_lbt = 0u;
    plan.lbt_timeout_ms = 0u;

    st = ninlil_sx1262_phy_arm_tx(phy, &plan, frame, frame_len, out_error);
    if (st == NINLIL_SX1262_OK) {
        phy->last_consumed_permit_seq = permit->permit_sequence;
        phy->has_consumed_seq = 1u;
    }
    return st;
}
#endif /* !NINLIL_SX1262_PRODUCTION_BUILD */

ninlil_sx1262_status_t ninlil_sx1262_phy_start_rx(
    ninlil_sx1262_phy_t *phy,
    uint32_t timeout_ms,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_tx_permit_t synth;
    ninlil_sx1262_status_t st;
    uint64_t now;
    uint8_t f[4];
    uint8_t ldro;

    if (phy == NULL || phy->magic != PHY_MAGIC || phy->lifecycle != LIFE_READY) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NOT_READY, "rx");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (phy->in_flight != 0u || phy->state == NINLIL_SX1262_PHY_STATE_TX_ACTIVE) {
        set_err(phy, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "rxbusy");
        return NINLIL_SX1262_BUSY;
    }
    (void)memset(&synth, 0, sizeof(synth));
    synth.abi_version = NINLIL_SX1262_PHY_ABI_VERSION;
    synth.struct_size = (uint16_t)sizeof(synth);
    synth.frequency_hz = phy->profile.freq_hz_min;
    synth.bandwidth_hz = phy->profile.bandwidth_hz;
    synth.spreading_factor = phy->profile.sf_min;
    synth.coding_rate_denom = phy->profile.cr_denom_min;
    synth.preamble_symbols = phy->profile.preamble_min;
    synth.tx_power_mdb = phy->profile.tx_power_mdb_min;
    synth.max_airtime_us = 1000u;
    synth.frame_byte_length = 0u;
    ldro = (uint8_t)ninlil_sx1262_phy_ldro_auto_effective(
        synth.spreading_factor, synth.bandwidth_hz);
    phy->in_flight = 1u;
    phy->state = NINLIL_SX1262_PHY_STATE_CONFIGURING;
    st = configure_lora(phy, &synth, NULL, 0u, 0, ldro, out_error);
    if (st != NINLIL_SX1262_OK) {
        phy->in_flight = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        return st;
    }
    st = ant_sw_set(phy, 1, out_error);
    if (st != NINLIL_SX1262_OK) {
        phy->in_flight = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        return st;
    }
    sat_inc(&phy->stats.ant_sw_rx);
    f[0] = CMD_SET_RX;
    f[1] = 0xFFu;
    f[2] = 0xFFu;
    f[3] = 0xFFu; /* continuous until stop/timeout IRQ when device supports */
    st = cmd_n(phy, f, 4u, out_error);
    if (st != NINLIL_SX1262_OK) {
        (void)ant_sw_set(phy, 0, NULL);
        phy->in_flight = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_FAULT;
        return st;
    }
    sat_inc(&phy->stats.setrx_commands);
    sat_inc(&phy->stats.rx_starts);
    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
        (void)ant_sw_set(phy, 0, NULL);
        phy->in_flight = 0u;
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_SPI_FAIL, "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (timeout_ms == 0u) {
        timeout_ms = 5000u;
    }
    phy->op_deadline_ms = now + timeout_ms;
    phy->state = NINLIL_SX1262_PHY_STATE_RX_ACTIVE;
    phy->in_flight = 0u;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t finish_rx(
    ninlil_sx1262_phy_t *phy,
    uint16_t irq,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint8_t payload_len;
    uint8_t offset;
    uint32_t i;

    if ((irq & IRQ_HEADER_ERR) != 0u) {
        phy->rx_meta.classification = NINLIL_SX1262_RX_HEADER_ERROR;
        sat_inc(&phy->stats.rx_header_err);
        (void)clear_irq_all(phy, out_error);
        phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        return NINLIL_SX1262_OK;
    }
    if ((irq & IRQ_CRC_ERR) != 0u) {
        phy->rx_meta.classification = NINLIL_SX1262_RX_CRC_ERROR;
        sat_inc(&phy->stats.rx_crc_err);
        (void)clear_irq_all(phy, out_error);
        phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        return NINLIL_SX1262_OK;
    }
    if ((irq & IRQ_TIMEOUT) != 0u && (irq & IRQ_RX_DONE) == 0u) {
        phy->rx_meta.classification = NINLIL_SX1262_RX_TIMEOUT;
        (void)clear_irq_all(phy, out_error);
        phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        return NINLIL_SX1262_OK;
    }
    phy->spi_tx[0] = CMD_GET_RX_BUFFER_STATUS;
    phy->spi_tx[1] = 0u;
    phy->spi_tx[2] = 0u;
    phy->spi_tx[3] = 0u;
    st = spi_xfer(phy, 4u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    payload_len = phy->spi_rx[2];
    offset = phy->spi_rx[3];
    /*
     * payload_len is u8; MAX_FRAME is 255, so upper-bound is type-implied.
     * Keep zero-length as EMPTY (not a type-limits tautology under -Werror).
     */
    if (payload_len == 0u) {
        phy->rx_meta.classification = NINLIL_SX1262_RX_EMPTY;
        (void)clear_irq_all(phy, out_error);
        phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        return NINLIL_SX1262_OK;
    }
    if ((size_t)payload_len + 3u > SPI_CAP) {
        set_err(phy, out_error, NINLIL_SX1262_DEVICE_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_DEVICE_ERRORS,
            "rxlen");
        return NINLIL_SX1262_DEVICE_ERROR;
    }
    phy->spi_tx[0] = CMD_READ_BUFFER;
    phy->spi_tx[1] = offset;
    phy->spi_tx[2] = 0u;
    for (i = 0u; i < payload_len; ++i) {
        phy->spi_tx[3u + i] = 0u;
    }
    st = spi_xfer(phy, (size_t)payload_len + 3u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    for (i = 0u; i < payload_len; ++i) {
        phy->rx_payload[i] = phy->spi_rx[3u + i];
    }
    phy->rx_len = payload_len;
    phy->rx_meta.length = payload_len;
    phy->rx_meta.classification = NINLIL_SX1262_RX_OK;
    phy->rx_meta.radio_generation = phy->radio_generation;
    phy->rx_meta.irq_status = irq;
    /* GetPacketStatus: real RSSI/SNR from device (DS LoRa PacketStatus). */
    phy->spi_tx[0] = CMD_GET_PACKET_STATUS;
    phy->spi_tx[1] = 0u;
    phy->spi_tx[2] = 0u;
    phy->spi_tx[3] = 0u;
    phy->spi_tx[4] = 0u;
    st = spi_xfer(phy, 5u, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* rx[2]=RssiPkt, rx[3]=SnrPkt (signed), rx[4]=SignalRssiPkt */
    phy->rx_meta.rssi_dbm = (int16_t)(-((int)phy->spi_rx[2] / 2));
    phy->rx_meta.snr_db = (int8_t)((int8_t)phy->spi_rx[3] / 4);
    phy->rx_pending = 1u;
    sat_inc(&phy->stats.rx_ok);
    st = clear_irq_all(phy, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
    return NINLIL_SX1262_OK;
}

ninlil_sx1262_status_t ninlil_sx1262_phy_poll(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    uint16_t irq = 0u;
    ninlil_sx1262_status_t st;
    uint64_t now;
    int dio1 = 0;

    if (phy == NULL || phy->magic != PHY_MAGIC || phy->lifecycle != LIFE_READY) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NOT_READY, "poll");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (phy->in_flight != 0u) {
        set_err(phy, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "poll");
        return NINLIL_SX1262_BUSY;
    }
    if (phy->state != NINLIL_SX1262_PHY_STATE_TX_ACTIVE
        && phy->state != NINLIL_SX1262_PHY_STATE_RX_ACTIVE) {
        clear_err(out_error);
        return NINLIL_SX1262_OK;
    }
    if (phy->backend->bus_ops.now_ms(phy->backend->bus_ctx, &now) != 0) {
        set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL, "now");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (now >= phy->op_deadline_ms) {
        if (phy->state == NINLIL_SX1262_PHY_STATE_TX_ACTIVE) {
            sat_inc(&phy->stats.tx_timeout);
        } else {
            phy->rx_meta.classification = NINLIL_SX1262_RX_TIMEOUT;
        }
        st = set_standby_rc(phy, out_error);
        (void)ant_sw_set(phy, 0, NULL);
        phy->sealed_live = 0u;
        phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        return st == NINLIL_SX1262_OK ? NINLIL_SX1262_OK : st;
    }
    if (phy->irq_ops.dio1_is_high != NULL) {
        if (phy->irq_ops.dio1_is_high(phy->irq_ctx, &dio1) != 0) {
            set_err(phy, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL, "dio1");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (dio1 == 0) {
            clear_err(out_error);
            return NINLIL_SX1262_OK;
        }
    }
    phy->in_flight = 1u;
    st = get_irq(phy, &irq, out_error);
    if (st != NINLIL_SX1262_OK) {
        phy->in_flight = 0u;
        return st;
    }
    if (phy->state == NINLIL_SX1262_PHY_STATE_TX_ACTIVE) {
        if ((irq & IRQ_TX_DONE) != 0u) {
            (void)clear_irq_all(phy, out_error);
            (void)set_standby_rc(phy, out_error);
            (void)ant_sw_set(phy, 0, NULL);
            phy->sealed_live = 0u;
            sat_inc(&phy->stats.tx_ok);
            phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
        }
        phy->in_flight = 0u;
        clear_err(out_error);
        return NINLIL_SX1262_OK;
    }
    /* RX — DIO1 latched; owner task reads IRQ + buffer (no SPI in ISR). */
    if ((irq & (IRQ_RX_DONE | IRQ_CRC_ERR | IRQ_HEADER_ERR | IRQ_TIMEOUT))
        != 0u) {
        st = finish_rx(phy, irq, out_error);
        (void)ant_sw_set(phy, 0, NULL);
        phy->in_flight = 0u;
        return st;
    }
    phy->in_flight = 0u;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}

ninlil_sx1262_status_t ninlil_sx1262_phy_take_rx(
    ninlil_sx1262_phy_t *phy,
    uint8_t *out_frame,
    uint32_t out_capacity,
    ninlil_sx1262_rx_meta_t *out_meta,
    ninlil_sx1262_error_t *out_error)
{
    uint32_t i;

    if (phy == NULL || phy->magic != PHY_MAGIC) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "take");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (out_meta != NULL) {
        *out_meta = phy->rx_meta;
        out_meta->radio_generation = phy->radio_generation;
    }
    if (phy->rx_pending == 0u) {
        if (out_meta != NULL) {
            out_meta->classification = NINLIL_SX1262_RX_EMPTY;
            out_meta->length = 0u;
        }
        clear_err(out_error);
        return NINLIL_SX1262_OK;
    }
    if (out_frame == NULL || out_capacity < phy->rx_len) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "cap");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    for (i = 0u; i < phy->rx_len; ++i) {
        out_frame[i] = phy->rx_payload[i];
    }
    phy->rx_pending = 0u;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}

ninlil_sx1262_status_t ninlil_sx1262_phy_recover(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;

    if (phy == NULL || phy->magic != PHY_MAGIC || phy->lifecycle != LIFE_READY) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_RESET, NINLIL_SX1262_REASON_NOT_READY, "rec");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (phy->in_flight != 0u) {
        set_err(phy, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "rec");
        return NINLIL_SX1262_BUSY;
    }
    phy->in_flight = 1u;
    phy->state = NINLIL_SX1262_PHY_STATE_RECOVERY;
    st = set_standby_rc(phy, out_error);
    if (st == NINLIL_SX1262_OK) {
        st = clear_irq_all(phy, out_error);
    }
    (void)ant_sw_set(phy, 0, NULL);
    phy->sealed_live = 0u;
    if (phy->radio_generation < UINT64_MAX) {
        phy->radio_generation += 1u;
    }
    phy->rx_pending = 0u;
    phy->rx_len = 0u;
    (void)memset(&phy->rx_meta, 0, sizeof(phy->rx_meta));
    sat_inc(&phy->stats.recoveries);
    phy->state = (st == NINLIL_SX1262_OK) ? NINLIL_SX1262_PHY_STATE_IDLE
                                          : NINLIL_SX1262_PHY_STATE_FAULT;
    phy->in_flight = 0u;
    return st;
}

void ninlil_sx1262_phy_stats(
    const ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_phy_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (phy == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = phy->stats;
}

ninlil_sx1262_status_t ninlil_sx1262_phy_shutdown(
    ninlil_sx1262_phy_t *phy,
    ninlil_sx1262_error_t *out_error)
{
    if (phy == NULL) {
        set_err(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_SHUTDOWN, NINLIL_SX1262_REASON_NULL_ARG, "sd");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (phy->magic != PHY_MAGIC) {
        set_err(phy, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_SHUTDOWN, NINLIL_SX1262_REASON_NOT_READY, "sd");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (phy->lifecycle == LIFE_SHUTDOWN) {
        clear_err(out_error);
        return NINLIL_SX1262_OK;
    }
    (void)set_standby_rc(phy, out_error);
    phy->lifecycle = LIFE_SHUTDOWN;
    phy->state = NINLIL_SX1262_PHY_STATE_IDLE;
    phy->backend = NULL;
    clear_err(out_error);
    return NINLIL_SX1262_OK;
}
