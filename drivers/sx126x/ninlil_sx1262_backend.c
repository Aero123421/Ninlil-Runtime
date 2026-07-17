/*
 * R4 SX1262 control-plane backend (docs/28 audit P1 fixes).
 * Not RF TX. Not HIL/legal. Not SKU identification.
 */

#include "ninlil_sx1262_backend.h"

#include <string.h>

enum {
    LIFECYCLE_ZERO = 0,
    LIFECYCLE_INITING = 1,
    LIFECYCLE_READY = 2,
    LIFECYCLE_FAILED = 3,
    LIFECYCLE_SHUTDOWN = 4,
    SPI_XFER_CAP = 16
};

_Static_assert(NINLIL_SX1262_CMD_SET_TX == (uint8_t)0x83u, "SetTx ban");
_Static_assert(NINLIL_SX1262_CAL_ALL == (uint8_t)0x7Fu, "CAL_ALL");

static void clear_error(ninlil_sx1262_error_t *err)
{
    if (err != NULL) {
        (void)memset(err, 0, sizeof(*err));
    }
}

static void set_error(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error,
    ninlil_sx1262_status_t status,
    ninlil_sx1262_stage_t stage,
    ninlil_sx1262_reason_t reason,
    const char *hint)
{
    ninlil_sx1262_error_t local;
    size_t i;

    clear_error(&local);
    local.status = status;
    local.stage = stage;
    local.reason = reason;
    if (hint != NULL) {
        for (i = 0u; i + 1u < NINLIL_SX1262_HINT_BYTES && hint[i] != '\0'; ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (be != NULL) {
        be->last_error = local;
    }
    if (out_error != NULL) {
        *out_error = local;
    }
}

static void sat_inc(uint64_t *c)
{
    if (c != NULL) {
        *c = ninlil_sx1262_sat_add_u64(*c, 1u);
    }
}

static int mul_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (a != 0u && b > UINT64_MAX / a) {
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
    if (a > UINT64_MAX - b) {
        return 0;
    }
    *out = a + b;
    return 1;
}

static int ceil_div_u64(uint64_t num, uint64_t den, uint64_t *out)
{
    uint64_t q;
    uint64_t r;

    if (out == NULL || den == 0u) {
        return 0;
    }
    q = num / den;
    r = num % den;
    if (r != 0u) {
        if (q == UINT64_MAX) {
            return 0;
        }
        q += 1u;
    }
    *out = q;
    return 1;
}

int ninlil_sx1262_calc_busy_max_polls(
    uint32_t timeout_ms,
    uint32_t interval_us,
    uint32_t slack,
    uint64_t *out_max_polls)
{
    uint64_t timeout_us;
    uint64_t base;
    uint64_t total;

    if (out_max_polls == NULL || interval_us == 0u
        || interval_us > NINLIL_SX1262_BUSY_POLL_INTERVAL_MAX_US
        || slack < NINLIL_SX1262_BUSY_POLL_SLACK_MIN
        || slack > NINLIL_SX1262_BUSY_POLL_SLACK_MAX
        || timeout_ms == 0u || timeout_ms > NINLIL_SX1262_TIMEOUT_MS_MAX) {
        return 0;
    }
    if (!mul_u64((uint64_t)timeout_ms, 1000u, &timeout_us)) {
        return 0;
    }
    if (!ceil_div_u64(timeout_us, (uint64_t)interval_us, &base)) {
        return 0;
    }
    if (!add_u64(base, (uint64_t)slack, &total)) {
        return 0;
    }
    *out_max_polls = total;
    return 1;
}

int ninlil_sx1262_busy_deadline_reached(
    uint64_t start_ms,
    uint64_t now_ms,
    uint32_t timeout_ms)
{
    if (timeout_ms == 0u) {
        return 1;
    }
    /* Unsigned subtraction is wrap-safe for monotonic clocks. */
    return ((uint64_t)(now_ms - start_ms) >= (uint64_t)timeout_ms) ? 1 : 0;
}

static int pin_unset(uint32_t p)
{
    return p == NINLIL_SX1262_PIN_UNSET;
}

static int pins_distinct_n(const uint32_t *pins, size_t n)
{
    size_t i;
    size_t j;

    if (pins == NULL || n == 0u) {
        return 0;
    }
    for (i = 0u; i < n; ++i) {
        for (j = i + 1u; j < n; ++j) {
            if (pins[i] == pins[j]) {
                return 0;
            }
        }
    }
    return 1;
}

static int bus_ops_ok(const ninlil_sx1262_bus_ops_t *ops)
{
    return ops != NULL && ops->reset_assert != NULL
        && ops->reset_deassert != NULL && ops->busy_is_high != NULL
        && ops->spi_transfer != NULL && ops->delay_us != NULL
        && ops->now_ms != NULL;
}

/*
 * First-init gate: OBJECT_INIT sentinel only (magic==0, lifecycle==ZERO).
 * Caller MUST zero-init via NINLIL_SX1262_OBJECT_INIT — not a full padding
 * scan and not a claim that uninitialized garbage is detectable (C UB).
 */
static int object_is_object_init_sentinel(const ninlil_sx1262_backend_object_t *o)
{
    return o->magic == 0u && o->lifecycle == 0u;
}

size_t ninlil_sx1262_object_size(void)
{
    return sizeof(ninlil_sx1262_backend_t);
}

size_t ninlil_sx1262_object_align(void)
{
    return _Alignof(ninlil_sx1262_backend_t);
}

static int cmd_status_accepted_mid(uint8_t cmd)
{
    return ninlil_sx1262_cmd_status_accepted_mid(cmd);
}

static int cmd_status_hard_fail(uint8_t cmd)
{
    return ninlil_sx1262_cmd_status_is_fail(cmd);
}

/* interval_us must be <= timeout_ms*1000 (overflow-safe). */
static int interval_fits_timeout_ms(uint32_t timeout_ms, uint32_t interval_us)
{
    uint64_t timeout_us;

    if (timeout_ms == 0u || interval_us == 0u) {
        return 0;
    }
    if (!mul_u64((uint64_t)timeout_ms, 1000u, &timeout_us)) {
        return 0;
    }
    return (uint64_t)interval_us <= timeout_us;
}

ninlil_sx1262_status_t ninlil_sx1262_validate_board_config(
    const ninlil_sx1262_board_config_t *config,
    const ninlil_sx1262_bus_ops_t *ops,
    ninlil_sx1262_error_t *out_error)
{
    int tcxo;
    int ant;
    uint16_t tcxo_mv;
    uint64_t dummy_polls;

    if (config == NULL || ops == NULL) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (config->abi_version != NINLIL_SX1262_ABI_VERSION
        || config->struct_size < (uint16_t)sizeof(*config)
        || config->reserved_zero != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_BAD_HEADER,
            "header");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (!bus_ops_ok(ops)) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_OPS_NULL, "ops");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (pin_unset(config->pin_nss) || pin_unset(config->pin_sck)
        || pin_unset(config->pin_mosi) || pin_unset(config->pin_miso)
        || pin_unset(config->pin_reset) || pin_unset(config->pin_busy)
        || pin_unset(config->pin_dio1)) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_PIN_UNSET, "pin");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    {
        const uint32_t req[7] = {
            config->pin_nss, config->pin_sck, config->pin_mosi,
            config->pin_miso, config->pin_reset, config->pin_busy,
            config->pin_dio1
        };

        if (!pins_distinct_n(req, 7u)) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_PIN_DUP, "dup");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
    }

    ant = (config->feature_flags & NINLIL_SX1262_FEATURE_ANT_SW_PRESENT) != 0u;
    tcxo = (config->feature_flags & NINLIL_SX1262_FEATURE_TCXO_PRESENT) != 0u;
    if (ant) {
        const uint32_t with_ant[8] = {
            config->pin_nss, config->pin_sck, config->pin_mosi,
            config->pin_miso, config->pin_reset, config->pin_busy,
            config->pin_dio1, config->pin_ant_sw
        };

        if (pin_unset(config->pin_ant_sw) || ops->ant_sw_set == NULL) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
                "ANT_SW");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
        /* ANT_SW must not collide with required pins (docs/28 §4.2). */
        if (!pins_distinct_n(with_ant, 8u)) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_PIN_DUP,
                "ANT_SW pin dup");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
    } else if (!pin_unset(config->pin_ant_sw) || ops->ant_sw_set != NULL) {
        /* Flag off: pin UNSET and unused callback must be NULL. */
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
            "ANT_SW mismatch");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    /* R4: SWSD003 1ms — not DS "typically 100us" as guaranteed minimum. */
    if (config->reset_pulse_us != NINLIL_SX1262_RESET_PULSE_US_R4) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_RESET_PULSE_SHORT,
            "reset_pulse_us must be 1000 (SWSD003)");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (config->reserved0 != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_RESERVED,
            "reserved0 nonzero");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (ant) {
        if (config->ant_sw_active_high > 1u) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
                "ant_sw_active_high");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
    } else if (config->ant_sw_active_high != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
            "ant polarity without ANT_SW");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (config->busy_timeout_ms == 0u
        || config->busy_timeout_ms > NINLIL_SX1262_TIMEOUT_MS_MAX
        || config->spi_busy_timeout_ms == 0u
        || config->spi_busy_timeout_ms > NINLIL_SX1262_TIMEOUT_MS_MAX
        || config->post_spi_busy_guard_us == 0u
        || config->busy_poll_interval_us < NINLIL_SX1262_BUSY_POLL_INTERVAL_MIN_US
        || config->busy_poll_interval_us > NINLIL_SX1262_BUSY_POLL_INTERVAL_MAX_US
        || config->busy_poll_slack < NINLIL_SX1262_BUSY_POLL_SLACK_MIN
        || config->busy_poll_slack > NINLIL_SX1262_BUSY_POLL_SLACK_MAX) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_TIMING_ZERO,
            "timing");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    /*
     * Correlation: busy_poll_interval_us must be <= each timeout_ms*1000
     * (else a single delay can exceed the deadline budget). Overflow-safe.
     */
    if (!interval_fits_timeout_ms(
            config->busy_timeout_ms, config->busy_poll_interval_us)
        || !interval_fits_timeout_ms(
               config->spi_busy_timeout_ms, config->busy_poll_interval_us)) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_TIMING_ZERO,
            "interval_us > timeout_us");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (!ninlil_sx1262_calc_busy_max_polls(
            config->busy_timeout_ms,
            config->busy_poll_interval_us,
            config->busy_poll_slack,
            &dummy_polls)
        || !ninlil_sx1262_calc_busy_max_polls(
               config->spi_busy_timeout_ms,
               config->busy_poll_interval_us,
               config->busy_poll_slack,
               &dummy_polls)) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_OVERFLOW,
            "poll overflow");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (config->regulator_mode != NINLIL_SX1262_REG_MODE_LDO
        && config->regulator_mode != NINLIL_SX1262_REG_MODE_DCDC) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_REGULATOR,
            "regulator");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    if (tcxo) {
        /* docs/28: tcxo_delay_rtc_steps must be nonzero when TCXO_PRESENT */
        if (config->tcxo_delay_rtc_steps == 0u
            || (config->tcxo_delay_rtc_steps & 0xFF000000u) != 0u
            || config->tcxo_busy_timeout_ms == 0u
            || config->tcxo_busy_timeout_ms > NINLIL_SX1262_TIMEOUT_MS_MAX) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_TCXO_DELAY,
                "tcxo timing / zero delay steps");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
        if (!interval_fits_timeout_ms(
                config->tcxo_busy_timeout_ms, config->busy_poll_interval_us)) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_TIMING_ZERO,
                "tcxo interval_us > timeout_us");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
        if (!ninlil_sx1262_calc_busy_max_polls(
                config->tcxo_busy_timeout_ms,
                config->busy_poll_interval_us,
                config->busy_poll_slack,
                &dummy_polls)) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_OVERFLOW,
                "tcxo poll overflow");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
        tcxo_mv = ninlil_sx1262_tcxo_voltage_mv(config->tcxo_voltage);
        if (tcxo_mv == 0u
            || config->vdd_op_mv <= (uint16_t)(tcxo_mv + 200u)) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
                NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_TCXO_VDD,
                "VDD/TCXO");
            return NINLIL_SX1262_INVALID_ARGUMENT;
        }
    } else if (config->tcxo_delay_rtc_steps != 0u
        || config->tcxo_busy_timeout_ms != 0u
        || config->tcxo_voltage != 0u || config->vdd_op_mv != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_FEATURE_MISMATCH,
            "TCXO params");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    if ((config->feature_flags
            & ~(NINLIL_SX1262_FEATURE_TCXO_PRESENT
                | NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH
                | NINLIL_SX1262_FEATURE_ANT_SW_PRESENT))
        != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_CONFIG, NINLIL_SX1262_REASON_RESERVED,
            "feature");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    clear_error(out_error);
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t wait_busy_low(
    ninlil_sx1262_backend_t *be,
    uint32_t timeout_ms,
    ninlil_sx1262_error_t *out_error)
{
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
        set_error(be, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_OVERFLOW,
            "max_polls");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (be->bus_ops.now_ms(be->bus_ctx, &start) != 0) {
        set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
            "now_ms");
        return NINLIL_SX1262_BUS_ERROR;
    }
    for (polls = 0u; polls < max_polls; ++polls) {
        high = 0;
        if (be->bus_ops.busy_is_high(be->bus_ctx, &high) != 0) {
            set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "busy read");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (high == 0) {
            return NINLIL_SX1262_OK;
        }
        if (be->bus_ops.delay_us(
                be->bus_ctx, be->board.busy_poll_interval_us)
            != 0) {
            set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "poll delay");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (be->bus_ops.now_ms(be->bus_ctx, &now) != 0) {
            set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "now_ms loop");
            return NINLIL_SX1262_BUS_ERROR;
        }
        if (ninlil_sx1262_busy_deadline_reached(start, now, timeout_ms) != 0) {
            sat_inc(&be->stats.busy_timeouts);
            set_error(be, out_error, NINLIL_SX1262_BUSY_TIMEOUT,
                NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_BUSY_STUCK,
                "BUSY deadline");
            return NINLIL_SX1262_BUSY_TIMEOUT;
        }
    }
    sat_inc(&be->stats.busy_timeouts);
    set_error(be, out_error, NINLIL_SX1262_BUSY_TIMEOUT,
        NINLIL_SX1262_STAGE_BUSY_WAIT, NINLIL_SX1262_REASON_BUSY_STUCK,
        "BUSY poll cap (frozen clock)");
    return NINLIL_SX1262_BUSY_TIMEOUT;
}

static ninlil_sx1262_status_t decode_status_byte(
    ninlil_sx1262_backend_t *be,
    uint8_t status_byte,
    int require_stby_rc,
    int enforce_accepted_set,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t mode;
    uint8_t cmd;

    be->last_status_byte = status_byte;
    mode = ninlil_sx1262_status_chip_mode(status_byte);
    cmd = ninlil_sx1262_status_cmd_status(status_byte);
    be->last_chip_mode = mode;
    be->last_cmd_status = cmd;
    sat_inc(&be->stats.status_checks);

    if (ninlil_sx1262_cmd_status_is_fail(cmd)) {
        set_error(be, out_error, NINLIL_SX1262_STATUS_INVALID,
            NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
            "cmd_status 3/4/5");
        return NINLIL_SX1262_STATUS_INVALID;
    }
    if (enforce_accepted_set != 0 && !cmd_status_accepted_mid(cmd)) {
        set_error(be, out_error, NINLIL_SX1262_STATUS_INVALID,
            NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
            "cmd_status not in accepted set");
        return NINLIL_SX1262_STATUS_INVALID;
    }
    if (require_stby_rc != 0 && mode != NINLIL_SX1262_CHIP_MODE_STBY_RC) {
        set_error(be, out_error, NINLIL_SX1262_STATUS_INVALID,
            NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CHIP_MODE,
            "mode not STBY_RC");
        return NINLIL_SX1262_STATUS_INVALID;
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t spi_xfer_allowlisted(
    ninlil_sx1262_backend_t *be,
    const uint8_t *tx,
    uint8_t *rx,
    size_t len,
    uint32_t busy_timeout_ms,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint8_t local_rx[SPI_XFER_CAP];
    int rc;

    if (tx == NULL || len == 0u || len > (size_t)SPI_XFER_CAP) {
        set_error(be, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_NULL_ARG, "spi");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (!ninlil_sx1262_cmd_is_allowlisted(tx[0])
        || ninlil_sx1262_cmd_is_rf_banned(tx[0])
        || !ninlil_sx1262_cmd_frame_valid(tx, len)) {
        sat_inc(&be->stats.opcode_denied);
        set_error(be, out_error, NINLIL_SX1262_UNSUPPORTED,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_OPCODE_DENIED,
            "opcode/schema denied");
        return NINLIL_SX1262_UNSUPPORTED;
    }

    st = wait_busy_low(be, busy_timeout_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    (void)memset(local_rx, 0, sizeof(local_rx));
    sat_inc(&be->stats.spi_xfers);
    /* Always full-duplex — never discard MISO. */
    rc = be->bus_ops.spi_transfer(be->bus_ctx, tx, local_rx, len);
    if (rc != 0) {
        /*
         * Transport failure: command may not have started on the device.
         * Do not run post-BUSY sync or decode status (docs/28 §6.3 transport).
         * Lifetime: no pending SPI ownership at portable layer (port handles).
         */
        sat_inc(&be->stats.spi_errors);
        set_error(be, out_error, NINLIL_SX1262_SPI_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL,
            "spi_transfer");
        return NINLIL_SX1262_SPI_ERROR;
    }
    if (rx != NULL) {
        (void)memcpy(rx, local_rx, len);
    }
    /*
     * MUST: complete this command's BUSY cycle (post guard + BUSY low)
     * before decoding rx[1] status — even when status will be 3/4/5/1/6.
     */
    if (be->bus_ops.delay_us(
            be->bus_ctx, be->board.post_spi_busy_guard_us)
        != 0) {
        set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_FAIL,
            "post guard");
        return NINLIL_SX1262_BUS_ERROR;
    }
    st = wait_busy_low(be, busy_timeout_ms, out_error);
    if (st == NINLIL_SX1262_BUSY_TIMEOUT) {
        set_error(be, out_error, NINLIL_SX1262_SPI_TIMEOUT,
            NINLIL_SX1262_STAGE_SPI, NINLIL_SX1262_REASON_SPI_TIMEOUT,
            "post-SPI BUSY");
        return NINLIL_SX1262_SPI_TIMEOUT;
    }
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /*
     * DS Rev2.2 Table 10-1 / 13-85: rx[0]=RFU, rx[1]=Status.
     * After first post-reset status: mid-init accepted set {0,2} only
     * (rejects RFU=1, fail 3/4/5, TX_DONE=6).
     */
    if (len >= 2u && be->post_reset_status_seen != 0u) {
        uint8_t status_b = local_rx[1];
        uint8_t prev_cmd = ninlil_sx1262_status_cmd_status(status_b);

        be->last_status_byte = status_b;
        be->last_chip_mode = ninlil_sx1262_status_chip_mode(status_b);
        be->last_cmd_status = prev_cmd;
        if (cmd_status_hard_fail(prev_cmd) || !cmd_status_accepted_mid(prev_cmd)) {
            set_error(be, out_error, NINLIL_SX1262_STATUS_INVALID,
                NINLIL_SX1262_STAGE_STATUS, NINLIL_SX1262_REASON_BAD_CMD_STATUS,
                "rx[1] cmd_status not in mid-init accepted {0,2} after BUSY");
            return NINLIL_SX1262_STATUS_INVALID;
        }
    }
    return NINLIL_SX1262_OK;
}

static ninlil_sx1262_status_t cmd_get_status(
    ninlil_sx1262_backend_t *be,
    int require_stby_rc,
    int enforce_accepted,
    uint32_t busy_ms,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[2];
    uint8_t rx[2];
    ninlil_sx1262_status_t st;

    tx[0] = NINLIL_SX1262_CMD_GET_STATUS;
    tx[1] = NINLIL_SX1262_SPI_NOP;
    rx[0] = 0u;
    rx[1] = 0u;
    st = spi_xfer_allowlisted(be, tx, rx, 2u, busy_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /* DS Table 10-1: rx[0]=RFU, rx[1]=Status (GetStatus 2B frame). */
    return decode_status_byte(
        be, rx[1], require_stby_rc, enforce_accepted, out_error);
}

/*
 * After every non-GetStatus write: mandatory GetStatus to verify previous cmd.
 */
static ninlil_sx1262_status_t verify_prev_cmd_status(
    ninlil_sx1262_backend_t *be,
    uint32_t busy_ms,
    ninlil_sx1262_error_t *out_error)
{
    return cmd_get_status(be, 0, 1, busy_ms, out_error);
}

static ninlil_sx1262_status_t cmd_write_then_verify(
    ninlil_sx1262_backend_t *be,
    const uint8_t *tx,
    size_t len,
    uint32_t busy_ms,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;

    st = spi_xfer_allowlisted(be, tx, NULL, len, busy_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    return verify_prev_cmd_status(be, busy_ms, out_error);
}

static ninlil_sx1262_status_t cmd_get_device_errors(
    ninlil_sx1262_backend_t *be,
    uint16_t *out_errors,
    uint32_t busy_ms,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[4];
    uint8_t rx[4];
    ninlil_sx1262_status_t st;

    tx[0] = NINLIL_SX1262_CMD_GET_DEVICE_ERRORS;
    tx[1] = NINLIL_SX1262_SPI_NOP;
    tx[2] = NINLIL_SX1262_SPI_NOP;
    tx[3] = NINLIL_SX1262_SPI_NOP;
    (void)memset(rx, 0, sizeof(rx));
    st = spi_xfer_allowlisted(be, tx, rx, 4u, busy_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    *out_errors = (uint16_t)(((uint16_t)rx[2] << 8) | (uint16_t)rx[3]);
    be->last_device_errors = *out_errors;
    /* GetDeviceErrors is a read path; still verify with GetStatus for closed set */
    return verify_prev_cmd_status(be, busy_ms, out_error);
}

static ninlil_sx1262_status_t cmd_clr_device_errors(
    ninlil_sx1262_backend_t *be,
    uint32_t busy_ms,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[3];

    tx[0] = NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS;
    tx[1] = NINLIL_SX1262_SPI_NOP;
    tx[2] = NINLIL_SX1262_SPI_NOP;
    return cmd_write_then_verify(be, tx, 3u, busy_ms, out_error);
}

static ninlil_sx1262_status_t cmd_set_regulator(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[2];

    tx[0] = NINLIL_SX1262_CMD_SET_REGULATOR_MODE;
    tx[1] = be->board.regulator_mode;
    return cmd_write_then_verify(
        be, tx, 2u, be->board.spi_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t cmd_set_standby_rc(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[2];

    tx[0] = NINLIL_SX1262_CMD_SET_STANDBY;
    tx[1] = NINLIL_SX1262_STANDBY_CFG_RC;
    return cmd_write_then_verify(
        be, tx, 2u, be->board.spi_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t cmd_set_dio2(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[2];

    tx[0] = NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL;
    tx[1] = 1u;
    return cmd_write_then_verify(
        be, tx, 2u, be->board.spi_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t cmd_set_dio3_tcxo(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[5];
    uint32_t d;

    d = be->board.tcxo_delay_rtc_steps & 0x00FFFFFFu;
    tx[0] = NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL;
    tx[1] = be->board.tcxo_voltage;
    tx[2] = (uint8_t)((d >> 16) & 0xFFu);
    tx[3] = (uint8_t)((d >> 8) & 0xFFu);
    tx[4] = (uint8_t)(d & 0xFFu);
    return cmd_write_then_verify(
        be, tx, 5u, be->board.tcxo_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t cmd_calibrate_all(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    uint8_t tx[2];

    tx[0] = NINLIL_SX1262_CMD_CALIBRATE;
    tx[1] = NINLIL_SX1262_CAL_ALL;
    return cmd_write_then_verify(
        be, tx, 2u, be->board.tcxo_busy_timeout_ms, out_error);
}

static ninlil_sx1262_status_t run_init_sequence(
    ninlil_sx1262_backend_t *be,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint16_t errors;
    uint32_t spi_ms;
    uint32_t tcxo_ms;
    int first_status;

    spi_ms = be->board.spi_busy_timeout_ms;
    tcxo_ms = be->board.tcxo_busy_timeout_ms;

    if (be->bus_ops.reset_assert(be->bus_ctx) != 0) {
        (void)be->bus_ops.reset_deassert(be->bus_ctx);
        set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_RESET, NINLIL_SX1262_REASON_RESET_FAIL,
            "reset_assert");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (be->bus_ops.delay_us(be->bus_ctx, be->board.reset_pulse_us) != 0) {
        (void)be->bus_ops.reset_deassert(be->bus_ctx);
        set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_RESET, NINLIL_SX1262_REASON_RESET_FAIL,
            "reset delay");
        return NINLIL_SX1262_BUS_ERROR;
    }
    if (be->bus_ops.reset_deassert(be->bus_ctx) != 0) {
        set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
            NINLIL_SX1262_STAGE_RESET, NINLIL_SX1262_REASON_RESET_FAIL,
            "reset_deassert");
        return NINLIL_SX1262_BUS_ERROR;
    }

    st = wait_busy_low(be, be->board.busy_timeout_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }

    /* First GetStatus after reset: mode STBY_RC; cmd_status not closed-set. */
    first_status = 1;
    st = cmd_get_status(be, 1, 0, spi_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    be->post_reset_status_seen = 1u;
    (void)first_status;

    st = cmd_get_device_errors(be, &errors, spi_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    be->first_device_errors = errors;

    if ((be->board.feature_flags & NINLIL_SX1262_FEATURE_TCXO_PRESENT) == 0u) {
        if (errors != 0u) {
            set_error(be, out_error, NINLIL_SX1262_DEVICE_ERROR,
                NINLIL_SX1262_STAGE_ERRORS, NINLIL_SX1262_REASON_DEVICE_ERRORS,
                "XTAL errors before clear");
            return NINLIL_SX1262_DEVICE_ERROR;
        }
    } else {
        /* DS §9.2.1: TCXO cold may set XOSC_START and/or IMG_CAL only. */
        if ((errors & (uint16_t)~NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED) != 0u) {
            set_error(be, out_error, NINLIL_SX1262_DEVICE_ERROR,
                NINLIL_SX1262_STAGE_ERRORS, NINLIL_SX1262_REASON_DEVICE_ERRORS,
                "TCXO cold: unexpected error bits");
            return NINLIL_SX1262_DEVICE_ERROR;
        }
        if ((errors & NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED) != 0u) {
            be->expected_cold_errors_latched = errors;
            sat_inc(&be->stats.expected_cold_errors_seen);
            st = cmd_clr_device_errors(be, spi_ms, out_error);
            if (st != NINLIL_SX1262_OK) {
                return st;
            }
        }
    }

    st = cmd_set_regulator(be, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    if ((be->board.feature_flags & NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH) != 0u) {
        st = cmd_set_dio2(be, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
    }
    if ((be->board.feature_flags & NINLIL_SX1262_FEATURE_TCXO_PRESENT) != 0u) {
        /* DS §9.2.1: SetDIO3 → CAL_ALL → post error must be zero. */
        st = cmd_set_dio3_tcxo(be, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
        st = cmd_calibrate_all(be, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
        st = cmd_get_status(be, 0, 1, tcxo_ms, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
        st = cmd_get_device_errors(be, &errors, tcxo_ms, out_error);
        if (st != NINLIL_SX1262_OK) {
            return st;
        }
        if (errors != 0u) {
            set_error(be, out_error, NINLIL_SX1262_DEVICE_ERROR,
                NINLIL_SX1262_STAGE_CAL, NINLIL_SX1262_REASON_DEVICE_ERRORS,
                "post-cal errors");
            return NINLIL_SX1262_DEVICE_ERROR;
        }
    }

    st = cmd_set_standby_rc(be, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    st = cmd_get_status(be, 1, 1, spi_ms, out_error);
    if (st != NINLIL_SX1262_OK) {
        return st;
    }
    /*
     * ANT_SW: after control-plane SPI success, drive safe inactive level
     * before READY (docs/28 §4.2). Flag/callback contract validated earlier.
     */
    if ((be->board.feature_flags & NINLIL_SX1262_FEATURE_ANT_SW_PRESENT) != 0u
        && be->bus_ops.ant_sw_set != NULL) {
        if (be->bus_ops.ant_sw_set(be->bus_ctx, 0) != 0) {
            set_error(be, out_error, NINLIL_SX1262_BUS_ERROR,
                NINLIL_SX1262_STAGE_INIT, NINLIL_SX1262_REASON_SPI_FAIL,
                "ANT_SW safe level");
            return NINLIL_SX1262_BUS_ERROR;
        }
    }
    clear_error(out_error);
    return NINLIL_SX1262_OK;
}

ninlil_sx1262_status_t ninlil_sx1262_init(
    ninlil_sx1262_backend_object_t *object,
    const ninlil_sx1262_board_config_t *config,
    const ninlil_sx1262_bus_ops_t *ops,
    void *bus_ctx,
    ninlil_sx1262_backend_t **out_backend,
    ninlil_sx1262_error_t *out_error)
{
    ninlil_sx1262_status_t st;
    uint32_t prior_magic;
    uint32_t prior_life;
    ninlil_sx1262_stats_t preserved;
    int from_shutdown;

    if (object == NULL || config == NULL || ops == NULL || out_backend == NULL) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_INIT, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    *out_backend = NULL;
    if (((uintptr_t)(const void *)object % NINLIL_SX1262_OBJECT_ALIGN) != 0u) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_INIT, NINLIL_SX1262_REASON_NULL_ARG, "align");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }

    from_shutdown = 0;
    (void)memset(&preserved, 0, sizeof(preserved));
    if (object_is_object_init_sentinel(object)) {
        /* first init after OBJECT_INIT */
    } else {
        (void)memcpy(&prior_magic, &object->magic, sizeof(prior_magic));
        (void)memcpy(&prior_life, &object->lifecycle, sizeof(prior_life));
        if (prior_magic != NINLIL_SX1262_MAGIC
            || prior_life != (uint32_t)LIFECYCLE_SHUTDOWN) {
            set_error(NULL, out_error, NINLIL_SX1262_INVALID_STATE,
                NINLIL_SX1262_STAGE_INIT, NINLIL_SX1262_REASON_NOT_FRESH,
                "not OBJECT_INIT / not SHUTDOWN");
            return NINLIL_SX1262_INVALID_STATE;
        }
        from_shutdown = 1;
        preserved = object->stats;
    }

    st = ninlil_sx1262_validate_board_config(config, ops, out_error);
    if (st != NINLIL_SX1262_OK) {
        if (from_shutdown != 0) {
            sat_inc(&object->stats.config_reject);
        }
        return st;
    }

    (void)memset(object, 0, sizeof(*object));
    if (from_shutdown != 0) {
        object->stats = preserved;
    }
    object->magic = NINLIL_SX1262_MAGIC;
    object->lifecycle = (uint32_t)LIFECYCLE_INITING;
    object->in_flight = 1u;
    object->bus_ops = *ops;
    object->bus_ctx = bus_ctx;
    object->board = *config;
    sat_inc(&object->stats.init_attempts);

    st = run_init_sequence(object, out_error);
    object->in_flight = 0u;
    if (st != NINLIL_SX1262_OK) {
        sat_inc(&object->stats.init_fail);
        object->lifecycle = (uint32_t)LIFECYCLE_FAILED;
        (void)memset(&object->bus_ops, 0, sizeof(object->bus_ops));
        object->bus_ctx = NULL;
        *out_backend = object;
        return st;
    }
    sat_inc(&object->stats.init_ok);
    object->lifecycle = (uint32_t)LIFECYCLE_READY;
    *out_backend = object;
    clear_error(out_error);
    return NINLIL_SX1262_OK;
}

ninlil_sx1262_status_t ninlil_sx1262_request_transmit(
    ninlil_sx1262_backend_t *backend,
    const uint8_t *frame,
    uint32_t frame_len,
    ninlil_sx1262_error_t *out_error)
{
    (void)frame;
    (void)frame_len;
    if (backend == NULL) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (backend->magic != NINLIL_SX1262_MAGIC) {
        set_error(backend, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_NOT_READY, "magic");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (backend->in_flight != 0u) {
        sat_inc(&backend->stats.reentrant);
        set_error(backend, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "busy");
        return NINLIL_SX1262_BUSY;
    }
    sat_inc(&backend->stats.tx_deny);
    set_error(backend, out_error, NINLIL_SX1262_TX_DENIED,
        NINLIL_SX1262_STAGE_TX_DENY, NINLIL_SX1262_REASON_TX_DENIED,
        "R4 control-plane: physical TX denied");
    return NINLIL_SX1262_TX_DENIED;
}

void ninlil_sx1262_stats(
    const ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (backend == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = backend->stats;
}

void ninlil_sx1262_last_error(
    const ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_error_t *out_error)
{
    if (out_error == NULL) {
        return;
    }
    if (backend == NULL) {
        clear_error(out_error);
        return;
    }
    *out_error = backend->last_error;
}

ninlil_sx1262_status_t ninlil_sx1262_shutdown(
    ninlil_sx1262_backend_t *backend,
    ninlil_sx1262_error_t *out_error)
{
    if (backend == NULL) {
        set_error(NULL, out_error, NINLIL_SX1262_INVALID_ARGUMENT,
            NINLIL_SX1262_STAGE_SHUTDOWN, NINLIL_SX1262_REASON_NULL_ARG, "null");
        return NINLIL_SX1262_INVALID_ARGUMENT;
    }
    if (backend->magic != NINLIL_SX1262_MAGIC) {
        set_error(backend, out_error, NINLIL_SX1262_INVALID_STATE,
            NINLIL_SX1262_STAGE_SHUTDOWN, NINLIL_SX1262_REASON_NOT_READY,
            "magic");
        return NINLIL_SX1262_INVALID_STATE;
    }
    if (backend->in_flight != 0u) {
        sat_inc(&backend->stats.reentrant);
        set_error(backend, out_error, NINLIL_SX1262_BUSY,
            NINLIL_SX1262_STAGE_OWNER, NINLIL_SX1262_REASON_REENTRANT, "busy");
        return NINLIL_SX1262_BUSY;
    }
    if (backend->lifecycle == (uint32_t)LIFECYCLE_SHUTDOWN) {
        clear_error(out_error);
        return NINLIL_SX1262_OK;
    }
    (void)memset(&backend->bus_ops, 0, sizeof(backend->bus_ops));
    backend->bus_ctx = NULL;
    (void)memset(&backend->board, 0, sizeof(backend->board));
    backend->lifecycle = (uint32_t)LIFECYCLE_SHUTDOWN;
    sat_inc(&backend->stats.shutdowns);
    clear_error(out_error);
    return NINLIL_SX1262_OK;
}
