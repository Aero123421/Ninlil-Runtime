# Single authority for R4 SX1262 portable control-plane sources (D1).
# Host CMakeLists and ESP-IDF component include this file.
# Paths relative to repository root. Do not use file(GLOB).
# Spy / tests / RF TX production sources MUST NOT appear here.

set(NINLIL_SX1262_PORTABLE_RELATIVE_SOURCES
    drivers/sx126x/ninlil_sx1262_backend.c
)

# Pure timeout + SPI pending ownership + GPIO safe-init SM (host + ESP).
set(NINLIL_SX1262_ESP_PURE_RELATIVE_SOURCES
    ports/esp-idf/src/sx1262_spi_timeout_logic.c
    ports/esp-idf/src/sx1262_spi_pending_logic.c
    ports/esp-idf/src/sx1262_esp_gpio_init_logic.c
)

# ESP-IDF production-private bus adapter (SPI/GPIO). Not host pure tests.
# Authority allowlist for R4 ESP SX1262 TUs (gate scans this set; no fixed 2-file).
set(NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES
    ports/esp-idf/src/esp_idf_sx1262_bus.c
    ports/esp-idf/src/sx1262_spi_timeout_logic.c
    ports/esp-idf/src/sx1262_spi_pending_logic.c
    ports/esp-idf/src/sx1262_esp_gpio_init_logic.c
)
