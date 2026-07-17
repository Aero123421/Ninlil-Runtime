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
    ports/esp-idf/src/usb_cdc_ring_logic.c
    ports/esp-idf/src/usb_cdc_state_logic.c
    ports/esp-idf/src/usb_cdc_orch_logic.c
    # R2: ninlil_time_sample_t offsetof static_assert (ESP32-S3 / Xtensa ILP32 evidence).
    # Compile-only contract; no runtime dependency. Required in esp-idf CI.
    tests/radio/pcp_r2_time_sample_abi_static.c
)

set(NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES
    ports/esp-idf/src/esp_idf_clock.c
    ports/esp-idf/src/esp_idf_entropy.c
    ports/esp-idf/src/esp_idf_execution.c
    ports/esp-idf/src/esp_idf_owner_task.c
    ports/esp-idf/src/esp_idf_cell_agent.c
    ports/esp-idf/src/esp_idf_loopback_tx_permit.c
    ports/esp-idf/src/esp_idf_usb_cdc.c
)

# U2 pure CDC sources that host CTest can compile without ESP-IDF/TinyUSB.
set(NINLIL_ESP_IDF_USB_CDC_PURE_RELATIVE_SOURCES
    ports/esp-idf/src/usb_cdc_ring_logic.c
    ports/esp-idf/src/usb_cdc_state_logic.c
    ports/esp-idf/src/usb_cdc_orch_logic.c
)

set(NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES
    ${NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES}
    ${NINLIL_ESP_IDF_PORT_BACKEND_RELATIVE_SOURCES}
)
