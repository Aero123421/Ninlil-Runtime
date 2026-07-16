# Single authority for ESP-IDF port-owned platform adapter sources.
# Paths relative to repository root. Do not use file(GLOB).

set(NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES
    ports/esp-idf/src/clock_logic.c
    ports/esp-idf/src/clock_init_logic.c
    ports/esp-idf/src/entropy_logic.c
    ports/esp-idf/src/entropy_lifecycle_logic.c
    ports/esp-idf/src/entropy_publish_logic.c
    ports/esp-idf/src/execution_logic.c
    ports/esp-idf/src/execution_init_logic.c
)

set(NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES
    ports/esp-idf/src/esp_idf_clock.c
    ports/esp-idf/src/esp_idf_entropy.c
    ports/esp-idf/src/esp_idf_execution.c
)

set(NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES
    ${NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES}
    ${NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES}
)
