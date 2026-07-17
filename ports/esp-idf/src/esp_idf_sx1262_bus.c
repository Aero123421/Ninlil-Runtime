/*
 * ESP-IDF SX1262 bus — R4 control-plane.
 * Finite SPI via queue_trans + get_trans_result (ESP-IDF v5.5.3).
 * Pending ownership drain after get_result timeout (docs/28 §6.4).
 * No spi_device_polling_transmit (portMAX_DELAY).
 */

#include "ninlil_esp_idf/sx1262_bus.h"

#include "sx1262_esp_gpio_init_logic.h"
#include "sx1262_spi_pending_logic.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Busy-wait delays up to this many us (covers NRESET 100us..1ms accurately). */
enum { DELAY_US_BUSY_WAIT_MAX = 5000u };

/*
 * Primary compile checks vs real ESP-IDF spi_transaction_t (Xtensa/C11).
 * Portable header only guarantees max_align_t; here we pin the actual type.
 */
_Static_assert(
    sizeof(spi_transaction_t) <= NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES,
    "spi_transaction_t must fit in aligned trans_storage");
_Static_assert(
    _Alignof(spi_transaction_t) <= _Alignof(max_align_t),
    "spi_transaction_t align must be <= max_align_t");
_Static_assert(
    (offsetof(ninlil_esp_idf_sx1262_bus_t, trans_storage)
        % _Alignof(spi_transaction_t))
        == 0u,
    "trans_storage offset must satisfy spi_transaction_t alignment");

static void own_from_bus(
    const ninlil_esp_idf_sx1262_bus_t *bus,
    ninlil_sx1262_spi_own_t *own)
{
    own->life = bus->lifecycle;
    own->pend = bus->pending_state;
    own->poisoned = bus->poisoned;
    own->drain_attempts = bus->drain_attempts;
    own->max_drain_attempts = bus->max_drain_attempts;
}

static void own_to_bus(
    ninlil_esp_idf_sx1262_bus_t *bus,
    const ninlil_sx1262_spi_own_t *own)
{
    bus->lifecycle = own->life;
    bus->pending_state = own->pend;
    bus->poisoned = own->poisoned;
    bus->drain_attempts = own->drain_attempts;
    bus->max_drain_attempts = own->max_drain_attempts;
}

static int in_isr(void)
{
    return xPortInIsrContext() != 0 ? 1 : 0;
}

static int ticks_for_bus(
    const ninlil_esp_idf_sx1262_bus_t *bus,
    TickType_t *out_ticks)
{
    uint32_t ticks_u32;

    if (bus == NULL || out_ticks == NULL) {
        return 1;
    }
    if (!ninlil_esp_idf_sx1262_ms_to_ticks(
            bus->cfg.spi_timeout_ms, (uint32_t)configTICK_RATE_HZ, &ticks_u32)) {
        return 1;
    }
    *out_ticks = (TickType_t)ticks_u32;
    return 0;
}

static int bus_reset_assert(void *ctx)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;

    if (bus == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE
        || bus->poisoned != 0u) {
        return 1;
    }
    return gpio_set_level((gpio_num_t)bus->cfg.pin_reset, 0) == ESP_OK ? 0 : 1;
}

static int bus_reset_deassert(void *ctx)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;

    if (bus == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE) {
        return 1;
    }
    return gpio_set_level((gpio_num_t)bus->cfg.pin_reset, 1) == ESP_OK ? 0 : 1;
}

static int bus_busy_is_high(void *ctx, int *out_high)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;

    if (bus == NULL || out_high == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE) {
        return 1;
    }
    *out_high = gpio_get_level((gpio_num_t)bus->cfg.pin_busy) != 0 ? 1 : 0;
    return 0;
}

static int bus_spi_transfer(
    void *ctx,
    const uint8_t *tx,
    uint8_t *rx,
    size_t len)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;
    ninlil_sx1262_spi_own_t own;
    spi_transaction_t *t;
    spi_transaction_t *ret;
    TickType_t ticks;
    esp_err_t err;

    if (bus == NULL || tx == NULL || len == 0u || len > sizeof(bus->tx_scratch)
        || in_isr() || bus->spi_handle == NULL) {
        return 1;
    }
    own_from_bus(bus, &own);
    if (!ninlil_sx1262_spi_own_can_transfer(&own)) {
        return 1;
    }
    if (ninlil_sx1262_cmd_is_rf_banned(tx[0])
        || !ninlil_sx1262_cmd_is_allowlisted(tx[0])) {
        return 1;
    }
    if (ticks_for_bus(bus, &ticks) != 0) {
        return 1;
    }

    (void)memcpy(bus->tx_scratch, tx, len);
    (void)memset(bus->rx_scratch, 0, sizeof(bus->rx_scratch));
    /* Well-defined: trans_storage is _Alignas(max_align_t); asserts above. */
    t = (spi_transaction_t *)(void *)&bus->trans_storage[0];
    (void)memset(t, 0, sizeof(*t));
    t->length = (uint32_t)(len * 8u);
    t->tx_buffer = bus->tx_scratch;
    t->rx_buffer = bus->rx_scratch;

    err = spi_device_queue_trans(
        (spi_device_handle_t)bus->spi_handle, t, ticks);
    if (err != ESP_OK) {
        bus->poisoned = 1u;
        return 1;
    }
    if (!ninlil_sx1262_spi_own_on_queued(&own)) {
        bus->poisoned = 1u;
        bus->pending_trans = t; /* still must drain if driver accepted */
        own_to_bus(bus, &own);
        return 1;
    }
    bus->pending_trans = t;
    own_to_bus(bus, &own);

    ret = NULL;
    err = spi_device_get_trans_result(
        (spi_device_handle_t)bus->spi_handle, &ret, ticks);
    own_from_bus(bus, &own);
    if (err == ESP_OK && ret == t) {
        if (!ninlil_sx1262_spi_own_on_result_ok(&own)) {
            bus->poisoned = 1u;
            own_to_bus(bus, &own);
            return 1;
        }
        bus->pending_trans = NULL;
        own_to_bus(bus, &own);
        if (rx != NULL) {
            (void)memcpy(rx, bus->rx_scratch, len);
        }
        return 0;
    }

    /*
     * Timeout / mismatch: ESP-IDF keeps the descriptor until a later
     * get_trans_result. Do NOT null pending_trans. Poison further SPI.
     */
    (void)ninlil_sx1262_spi_own_on_result_timeout(&own);
    /* pending_trans stays = t */
    own_to_bus(bus, &own);
    return 1;
}

static int bus_delay_us(void *ctx, uint32_t us)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;
    uint32_t ticks_u32;

    if (bus == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE) {
        return 1;
    }
    if (us == 0u) {
        return 0;
    }
    if (us <= (uint32_t)DELAY_US_BUSY_WAIT_MAX) {
        esp_rom_delay_us(us);
        return 0;
    }
    if (!ninlil_esp_idf_sx1262_us_to_ticks_ceil(
            us, (uint32_t)configTICK_RATE_HZ, &ticks_u32)) {
        return 1;
    }
    vTaskDelay((TickType_t)ticks_u32);
    return 0;
}

static int bus_now_ms(void *ctx, uint64_t *out_ms)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;
    int64_t us;

    if (bus == NULL || out_ms == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE) {
        return 1;
    }
    us = esp_timer_get_time();
    if (us < 0) {
        return 1;
    }
    *out_ms = (uint64_t)us / 1000u;
    return 0;
}

/* Map logical active (1) / inactive (0) through configured polarity. */
static int ant_gpio_level(const ninlil_esp_idf_sx1262_bus_t *bus, int active)
{
    if (active != 0) {
        return ninlil_sx1262_ant_active_level(bus->cfg.ant_sw_active_high);
    }
    return ninlil_sx1262_ant_inactive_level(bus->cfg.ant_sw_active_high);
}

static int bus_ant_sw_set(void *ctx, int active)
{
    ninlil_esp_idf_sx1262_bus_t *bus = (ninlil_esp_idf_sx1262_bus_t *)ctx;

    if (bus == NULL || in_isr()
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE
        || bus->cfg.pin_ant_sw < 0) {
        return 1;
    }
    return gpio_set_level(
               (gpio_num_t)bus->cfg.pin_ant_sw, ant_gpio_level(bus, active))
            == ESP_OK
        ? 0
        : 1;
}

/* Drive safe levels after output GPIO config (RESET deasserted, ANT inactive). */
static int drive_safe_output_levels(
    const ninlil_esp_idf_sx1262_bus_config_t *config,
    int with_ant)
{
    int ant_inactive;

    if (gpio_set_level((gpio_num_t)config->pin_reset, 1) != ESP_OK) {
        return 1;
    }
    if (with_ant != 0) {
        ant_inactive =
            ninlil_sx1262_ant_inactive_level(config->ant_sw_active_high);
        if (gpio_set_level((gpio_num_t)config->pin_ant_sw, ant_inactive)
            != ESP_OK) {
            return 1;
        }
    }
    return 0;
}

static void publish_ops(ninlil_esp_idf_sx1262_bus_t *bus, int with_ant)
{
    bus->ops.reset_assert = bus_reset_assert;
    bus->ops.reset_deassert = bus_reset_deassert;
    bus->ops.busy_is_high = bus_busy_is_high;
    bus->ops.spi_transfer = bus_spi_transfer;
    bus->ops.delay_us = bus_delay_us;
    bus->ops.now_ms = bus_now_ms;
    bus->ops.ant_sw_set = with_ant ? bus_ant_sw_set : NULL;
}

static void cleanup_partial(
    spi_host_device_t host,
    spi_device_handle_t handle,
    int bus_inited,
    int dev_added)
{
    if (dev_added != 0 && handle != NULL) {
        (void)spi_bus_remove_device(handle);
    }
    if (bus_inited != 0) {
        (void)spi_bus_free(host);
    }
}

int ninlil_esp_idf_sx1262_bus_drain(ninlil_esp_idf_sx1262_bus_t *bus)
{
    ninlil_sx1262_spi_own_t own;
    spi_transaction_t *ret;
    TickType_t ticks;
    esp_err_t err;

    if (bus == NULL || in_isr()
        || bus->magic != NINLIL_ESP_IDF_SX1262_BUS_MAGIC) {
        return 1;
    }
    own_from_bus(bus, &own);
    if (ninlil_sx1262_spi_own_is_reboot_required(&own)) {
        return 1;
    }
    if (!ninlil_sx1262_spi_own_needs_drain(&own)) {
        return own.pend == NINLIL_SX1262_SPI_PEND_NONE ? 0 : 1;
    }
    if (bus->spi_handle == NULL || bus->pending_trans == NULL) {
        /* Inconsistent — fail closed to reboot-required. */
        own.life = NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
        own.poisoned = 1u;
        own_to_bus(bus, &own);
        return 1;
    }
    if (ticks_for_bus(bus, &ticks) != 0) {
        return 1;
    }

    ret = NULL;
    err = spi_device_get_trans_result(
        (spi_device_handle_t)bus->spi_handle, &ret, ticks);
    own_from_bus(bus, &own);
    if (err == ESP_OK && ret == (spi_transaction_t *)bus->pending_trans) {
        if (!ninlil_sx1262_spi_own_on_drain_ok(&own)) {
            own_to_bus(bus, &own);
            return 1;
        }
        bus->pending_trans = NULL;
        own_to_bus(bus, &own);
        return 0;
    }
    (void)ninlil_sx1262_spi_own_on_drain_timeout(&own);
    own_to_bus(bus, &own);
    /* pending_trans retained until recovered or reboot-required */
    return 1;
}

int ninlil_esp_idf_sx1262_bus_init(
    ninlil_esp_idf_sx1262_bus_t *bus,
    const ninlil_esp_idf_sx1262_bus_config_t *config)
{
    spi_bus_config_t bus_cfg;
    spi_device_interface_config_t dev_cfg;
    spi_device_handle_t handle = NULL;
    gpio_config_t io;
    int with_ant;
    int bus_inited = 0;
    int dev_added = 0;
    esp_err_t err;
    uint32_t ticks_chk;
    uint32_t drain_max;
    uint64_t drain_wait_ms;
    ninlil_sx1262_spi_own_t own;

    if (bus == NULL || config == NULL || in_isr()) {
        return 1;
    }
    /*
     * Lifecycle trust only via magic (docs/28 §6.7).
     * Zero-init: magic==0, lifecycle==ZERO → first init.
     * After clean shutdown: magic==MAGIC, lifecycle==SHUTDOWN → re-init.
     * REBOOT_REQUIRED / ACTIVE / garbage → fail-closed.
     */
    if (bus->magic == 0u) {
        if (bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ZERO) {
            return 1;
        }
    } else if (bus->magic == NINLIL_ESP_IDF_SX1262_BUS_MAGIC) {
        own_from_bus(bus, &own);
        if (!ninlil_sx1262_spi_own_reinit_allowed(&own)
            || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_SHUTDOWN) {
            return 1;
        }
    } else {
        return 1;
    }
    if (config->abi_version != NINLIL_ESP_IDF_SX1262_BUS_ABI_VERSION
        || config->struct_size < (uint16_t)sizeof(*config)
        || config->reserved_zero != 0u
        || config->spi_clock_hz == 0u
        || config->spi_clock_hz > NINLIL_SX1262_SPI_CLOCK_MAX_HZ
        || config->spi_timeout_ms == 0u
        || config->spi_timeout_ms > NINLIL_SX1262_TIMEOUT_MS_MAX
        || !ninlil_esp_idf_sx1262_ms_to_ticks(
               config->spi_timeout_ms, (uint32_t)configTICK_RATE_HZ, &ticks_chk)
        || !ninlil_sx1262_spi_own_normalize_max_drain(
               config->spi_drain_max_attempts, &drain_max)
        || !ninlil_sx1262_spi_own_max_drain_wait_ms(
               drain_max, config->spi_timeout_ms, &drain_wait_ms)
        || config->spi_host < 0
        || config->spi_host >= (int)SPI_HOST_MAX) {
        return 1;
    }
    (void)drain_wait_ms; /* finite bound proven by normalize + mul */

    if (!GPIO_IS_VALID_OUTPUT_GPIO(config->pin_reset)
        || !GPIO_IS_VALID_GPIO(config->pin_busy)
        || !GPIO_IS_VALID_GPIO(config->pin_dio1)
        || !GPIO_IS_VALID_GPIO(config->pin_nss)
        || !GPIO_IS_VALID_GPIO(config->pin_sck)
        || !GPIO_IS_VALID_GPIO(config->pin_mosi)
        || !GPIO_IS_VALID_GPIO(config->pin_miso)) {
        return 1;
    }
    with_ant = config->pin_ant_sw >= 0 ? 1 : 0;
    if (with_ant && !GPIO_IS_VALID_OUTPUT_GPIO(config->pin_ant_sw)) {
        return 1;
    }
    if (with_ant) {
        if (config->ant_sw_active_high > 1u) {
            return 1;
        }
    } else if (config->ant_sw_active_high != 0u) {
        return 1;
    }
    if (config->reserved0[0] != 0u || config->reserved0[1] != 0u
        || config->reserved0[2] != 0u) {
        return 1;
    }
    {
        const int32_t pins[7] = {
            config->pin_nss, config->pin_sck, config->pin_mosi,
            config->pin_miso, config->pin_reset, config->pin_busy,
            config->pin_dio1
        };
        int i;
        int j;

        for (i = 0; i < 7; ++i) {
            for (j = i + 1; j < 7; ++j) {
                if (pins[i] == pins[j]) {
                    return 1;
                }
            }
            if (with_ant && pins[i] == config->pin_ant_sw) {
                return 1;
            }
        }
    }

    /*
     * Safe init order (docs/28 §6.5):
     * 1) configure outputs → 2) RESET high + ANT inactive → 3) inputs
     * Later SPI/bus failure keeps safe levels (outputs already driven).
     */
    (void)memset(&io, 0, sizeof(io));
    io.mode = GPIO_MODE_OUTPUT;
    io.pin_bit_mask = (1ULL << (unsigned)config->pin_reset);
    if (with_ant) {
        io.pin_bit_mask |= (1ULL << (unsigned)config->pin_ant_sw);
    }
    if (gpio_config(&io) != ESP_OK) {
        return 1;
    }
    if (drive_safe_output_levels(config, with_ant) != 0) {
        return 1;
    }
    (void)memset(&io, 0, sizeof(io));
    io.mode = GPIO_MODE_INPUT;
    io.pin_bit_mask = (1ULL << (unsigned)config->pin_busy)
        | (1ULL << (unsigned)config->pin_dio1);
    if (gpio_config(&io) != ESP_OK) {
        /* Keep RESET high / ANT inactive — already driven. */
        (void)drive_safe_output_levels(config, with_ant);
        return 1;
    }

    (void)memset(&bus_cfg, 0, sizeof(bus_cfg));
    bus_cfg.sclk_io_num = config->pin_sck;
    bus_cfg.mosi_io_num = config->pin_mosi;
    bus_cfg.miso_io_num = config->pin_miso;
    bus_cfg.quadwp_io_num = -1;
    bus_cfg.quadhd_io_num = -1;
    bus_cfg.max_transfer_sz = 32;

    (void)memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.clock_speed_hz = (int)config->spi_clock_hz;
    dev_cfg.mode = 0;
    dev_cfg.spics_io_num = config->pin_nss;
    dev_cfg.queue_size = 1; /* single outstanding for ownership clarity */

    err = spi_bus_initialize(
        (spi_host_device_t)config->spi_host, &bus_cfg, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) {
        (void)drive_safe_output_levels(config, with_ant);
        return 1;
    }
    bus_inited = 1;
    err = spi_bus_add_device(
        (spi_host_device_t)config->spi_host, &dev_cfg, &handle);
    if (err != ESP_OK) {
        cleanup_partial(
            (spi_host_device_t)config->spi_host, handle, bus_inited, 0);
        (void)drive_safe_output_levels(config, with_ant);
        return 1;
    }
    dev_added = 1;

    (void)memset(bus, 0, sizeof(*bus));
    bus->magic = NINLIL_ESP_IDF_SX1262_BUS_MAGIC;
    bus->cfg = *config;
    bus->spi_handle = handle;
    bus->pending_trans = NULL;
    ninlil_sx1262_spi_own_reset(&own, drain_max);
    own_to_bus(bus, &own);
    publish_ops(bus, with_ant);
    (void)dev_added;
    return 0;
}

int ninlil_esp_idf_sx1262_bus_shutdown(ninlil_esp_idf_sx1262_bus_t *bus)
{
    ninlil_sx1262_spi_own_t own;
    esp_err_t err;
    int drain_rc;

    if (bus == NULL || in_isr()) {
        return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_FAIL;
    }
    if (bus->magic != NINLIL_ESP_IDF_SX1262_BUS_MAGIC) {
        return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_FAIL;
    }
    own_from_bus(bus, &own);
    if (ninlil_sx1262_spi_own_is_reboot_required(&own)) {
        return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED;
    }
    if (bus->lifecycle == NINLIL_ESP_IDF_SX1262_BUS_LIFE_SHUTDOWN) {
        return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_OK;
    }

    /* Drain outstanding descriptor before remove_device (ESP_ERR_INVALID_STATE). */
    while (ninlil_sx1262_spi_own_needs_drain(&own)) {
        drain_rc = ninlil_esp_idf_sx1262_bus_drain(bus);
        own_from_bus(bus, &own);
        if (drain_rc == 0) {
            break;
        }
        if (ninlil_sx1262_spi_own_is_reboot_required(&own)) {
            return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED;
        }
    }
    own_from_bus(bus, &own);
    if (!ninlil_sx1262_spi_own_may_release_hw(&own)) {
        own.life = NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
        own.poisoned = 1u;
        own_to_bus(bus, &own);
        return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED;
    }

    if (bus->spi_handle != NULL) {
        err = spi_bus_remove_device((spi_device_handle_t)bus->spi_handle);
        if (err != ESP_OK) {
            /* Driver still holds work — do not free bus; hold lifetime. */
            own.life = NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
            own.poisoned = 1u;
            own_to_bus(bus, &own);
            return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED;
        }
        bus->spi_handle = NULL;
        err = spi_bus_free((spi_host_device_t)bus->cfg.spi_host);
        if (err != ESP_OK) {
            own.life = NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED;
            own.poisoned = 1u;
            own_to_bus(bus, &own);
            return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED;
        }
    }
    bus->pending_trans = NULL;
    ninlil_sx1262_spi_own_on_hw_released(&own);
    own_to_bus(bus, &own);
    (void)memset(&bus->ops, 0, sizeof(bus->ops));
    /* magic retained so SHUTDOWN re-init is distinguishable from garbage */
    return NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_OK;
}

int ninlil_esp_idf_sx1262_bus_reboot_required(
    const ninlil_esp_idf_sx1262_bus_t *bus)
{
    ninlil_sx1262_spi_own_t own;

    if (bus == NULL || bus->magic != NINLIL_ESP_IDF_SX1262_BUS_MAGIC) {
        return 0;
    }
    own_from_bus(bus, &own);
    return ninlil_sx1262_spi_own_is_reboot_required(&own);
}

const ninlil_sx1262_bus_ops_t *ninlil_esp_idf_sx1262_bus_ops(
    ninlil_esp_idf_sx1262_bus_t *bus)
{
    ninlil_sx1262_spi_own_t own;

    if (bus == NULL || in_isr()
        || bus->magic != NINLIL_ESP_IDF_SX1262_BUS_MAGIC) {
        return NULL;
    }
    own_from_bus(bus, &own);
    if (!ninlil_sx1262_spi_own_can_transfer(&own)
        && bus->lifecycle == NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE
        && bus->poisoned == 0u) {
        /* ACTIVE but pending — ops still published? Fail closed for xfer. */
    }
    if (bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE
        || bus->poisoned != 0u
        || ninlil_sx1262_spi_own_is_reboot_required(&own)) {
        return NULL;
    }
    return &bus->ops;
}

void *ninlil_esp_idf_sx1262_bus_ctx(ninlil_esp_idf_sx1262_bus_t *bus)
{
    if (bus == NULL || in_isr()
        || bus->magic != NINLIL_ESP_IDF_SX1262_BUS_MAGIC
        || bus->lifecycle != NINLIL_ESP_IDF_SX1262_BUS_LIFE_ACTIVE
        || bus->poisoned != 0u) {
        return NULL;
    }
    return bus;
}
