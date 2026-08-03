/*
 * Pure RF bus capability + SPI length admit boundaries (host).
 */
#include "sx1262_rf_bus_capability_logic.h"
#include "ninlil_sx1262_cmd.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Optional pure helpers if present in ESP pure unit link. */
int ninlil_esp_idf_sx1262_ms_to_ticks(
    uint32_t timeout_ms,
    uint32_t tick_rate_hz,
    uint32_t *out_ticks);

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(stderr, "%s:%d: FAIL %s\n", __FILE__, __LINE__, #c);  \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_control_only_deny_rf(void)
{
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY, NINLIL_SX1262_CMD_SET_TX, 4u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                10u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY,
                NINLIL_SX1262_CMD_SET_RF_FREQUENCY,
                5u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY, NINLIL_SX1262_CMD_SET_RX, 4u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY,
                NINLIL_SX1262_CMD_GET_STATUS,
                2u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY,
                NINLIL_SX1262_CMD_SET_STANDBY,
                2u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_CONTROL_ONLY,
                NINLIL_SX1262_CMD_CALIBRATE,
                2u)
        == 1);
    return 0;
}

static int test_rf_sole_admits_r9_set(void)
{
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, NINLIL_SX1262_CMD_SET_TX, 4u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, NINLIL_SX1262_CMD_SET_RX, 4u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_SET_RF_FREQUENCY,
                5u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                64u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_SET_TX_PARAMS,
                3u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0x8Au, 2u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0x12u, 4u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, NINLIL_SX1262_CMD_SET_CAD, 1u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0x88u, 8u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, NINLIL_SX1262_CMD_GET_STATUS, 2u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0xFFu, 2u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, NINLIL_SX1262_CMD_SET_TX, 0u)
        == 0);
    return 0;
}

static int test_shared_280_ceiling_boundaries(void)
{
    /*
     * Shared ceiling 280 with phy SPI_CAP / ESP scratch.
     * TX payload 30/31/64/255 → WriteBuffer SPI len 32/33/66/257.
     * RX ReadBuffer 255 → len 258.
     */
    REQUIRE(NINLIL_SX1262_BUS_RF_SPI_MAX_LEN == 280u);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                32u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                33u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                66u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                257u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                NINLIL_SX1262_BUS_RF_SPI_MAX_LEN)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE,
                NINLIL_SX1262_CMD_WRITE_BUFFER,
                NINLIL_SX1262_BUS_RF_SPI_MAX_LEN + 1u)
        == 0);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0x1Eu, 258u)
        == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                NINLIL_SX1262_BUS_CAP_RF_SOLE, (uint8_t)0x1Eu, 281u)
        == 0);
    return 0;
}

static int test_grant_revoke(void)
{
    uint32_t cap = NINLIL_SX1262_BUS_CAP_CONTROL_ONLY;

    REQUIRE(ninlil_sx1262_bus_cap_is_rf_sole(cap) == 0);
    REQUIRE(ninlil_sx1262_bus_cap_grant_rf_sole(&cap) == 0);
    REQUIRE(cap == NINLIL_SX1262_BUS_CAP_RF_SOLE);
    REQUIRE(ninlil_sx1262_bus_cap_is_rf_sole(cap) == 1);
    REQUIRE(ninlil_sx1262_bus_cap_grant_rf_sole(&cap) != 0);
    REQUIRE(ninlil_sx1262_bus_cap_revoke_rf(&cap) == 0);
    REQUIRE(cap == NINLIL_SX1262_BUS_CAP_CONTROL_ONLY);
    REQUIRE(ninlil_sx1262_bus_cap_grant_rf_sole(NULL) != 0);
    REQUIRE(ninlil_sx1262_bus_cap_revoke_rf(NULL) != 0);
    return 0;
}

static int test_r9_allowlist_vs_ban(void)
{
    REQUIRE(ninlil_sx1262_cmd_is_r9_rf_allowed(NINLIL_SX1262_CMD_SET_TX) == 1);
    REQUIRE(
        ninlil_sx1262_cmd_is_r9_rf_allowed(NINLIL_SX1262_CMD_WRITE_BUFFER) == 1);
    REQUIRE(ninlil_sx1262_cmd_is_r9_rf_allowed((uint8_t)0xD1u) == 0);
    REQUIRE(ninlil_sx1262_cmd_is_rf_banned(NINLIL_SX1262_CMD_SET_TX) == 1);
    REQUIRE(ninlil_sx1262_bus_spi_xfer_admitted(
                99u, NINLIL_SX1262_CMD_GET_STATUS, 2u)
        == 0);
    return 0;
}

int main(void)
{
    REQUIRE(test_control_only_deny_rf() == 0);
    REQUIRE(test_rf_sole_admits_r9_set() == 0);
    REQUIRE(test_shared_280_ceiling_boundaries() == 0);
    REQUIRE(test_grant_revoke() == 0);
    REQUIRE(test_r9_allowlist_vs_ban() == 0);
    (void)fprintf(stderr, "sx1262_esp_rf_bus_capability_test ok\n");
    return 0;
}
