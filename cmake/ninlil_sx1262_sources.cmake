# Single authority for R4 SX1262 portable control-plane sources (D1).
# Host CMakeLists and ESP-IDF component include this file.
# Paths relative to repository root. Do not use file(GLOB).
# Spy / tests / RF TX production sources MUST NOT appear here.

# R4 control-plane only (SetTx banned in this TU).
# Immutable board profiles (XIAO+Wio) used by release radio_hil + host tests.
set(NINLIL_SX1262_PORTABLE_R4_RELATIVE_SOURCES
    drivers/sx126x/ninlil_sx1262_backend.c
    drivers/sx126x/ninlil_sx1262_board_profiles.c
)

# R9 physical TX/RX (Proposed ADR-0025). Separate TU; sole edge with permit.
# ESP packages phy only when CONFIG_NINLIL_ENABLE_SX1262_R9=y (default OFF).
set(NINLIL_SX1262_PHY_RELATIVE_SOURCES
    drivers/sx126x/ninlil_sx1262_phy.c
)

# R9 edge adapter (radio_hal sole edge). Host always; ESP gated with R9.
set(NINLIL_SX1262_R9_EDGE_RELATIVE_SOURCES
    src/radio/sx1262_r9_edge.c
)

# Host portable D1 archive: R4 + R9 phy (phy fail-closed without permit).
set(NINLIL_SX1262_PORTABLE_RELATIVE_SOURCES
    ${NINLIL_SX1262_PORTABLE_R4_RELATIVE_SOURCES}
    ${NINLIL_SX1262_PHY_RELATIVE_SOURCES}
)

# ESP default package: R4 only (zero R9 symbols unless Kconfig enables R9).
set(NINLIL_SX1262_ESP_DEFAULT_RELATIVE_SOURCES
    ${NINLIL_SX1262_PORTABLE_R4_RELATIVE_SOURCES}
)

# Pure timeout + SPI pending ownership + GPIO safe-init SM + RF capability (host + ESP).
set(NINLIL_SX1262_ESP_PURE_RELATIVE_SOURCES
    ports/esp-idf/src/sx1262_spi_timeout_logic.c
    ports/esp-idf/src/sx1262_spi_pending_logic.c
    ports/esp-idf/src/sx1262_esp_gpio_init_logic.c
    ports/esp-idf/src/sx1262_rf_bus_capability_logic.c
)

# ESP-IDF production-private bus adapter (SPI/GPIO). Not host pure tests.
# Authority allowlist for R4 ESP SX1262 TUs (gate scans this set; no fixed 2-file).
set(NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES
    ports/esp-idf/src/esp_idf_sx1262_bus.c
    ports/esp-idf/src/sx1262_spi_timeout_logic.c
    ports/esp-idf/src/sx1262_spi_pending_logic.c
    ports/esp-idf/src/sx1262_esp_gpio_init_logic.c
    ports/esp-idf/src/sx1262_rf_bus_capability_logic.c
)
