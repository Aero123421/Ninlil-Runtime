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
    ports/esp-idf/src/owner_mailbox_logic.c
    ports/esp-idf/src/owner_lifecycle_logic.c
    ports/esp-idf/src/owner_publish_logic.c
    ports/esp-idf/src/owner_authority_logic.c
    ports/esp-idf/src/cell_assignment_logic.c
    ports/esp-idf/src/control_boundary_logic.c
    ports/esp-idf/src/loopback_tx_permit_logic.c
    ports/esp-idf/src/tx_gate_validate.c
    ports/esp-idf/src/pointer_range_logic.c
    ports/esp-idf/src/abi_header_stage_logic.c
    ports/esp-idf/src/owner_config_stage_logic.c
    ports/esp-idf/src/tx_gate_lease_logic.c
)

set(NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES
    ports/esp-idf/src/esp_idf_clock.c
    ports/esp-idf/src/esp_idf_entropy.c
    ports/esp-idf/src/esp_idf_execution.c
    ports/esp-idf/src/esp_idf_owner_task.c
    ports/esp-idf/src/esp_idf_cell_agent.c
    ports/esp-idf/src/esp_idf_loopback_tx_permit.c
)

set(NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES
    ${NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES}
    ${NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES}
)
