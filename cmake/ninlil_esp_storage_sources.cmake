# ESP durable-storage source authority. Keep host-only media out of target list.
set(NINLIL_ESP_STORAGE_MODEL_RELATIVE_SOURCES
    ports/esp-idf/storage/model/esp_storage_codec.c
    ports/esp-idf/storage/model/esp_storage_model.c
)

set(NINLIL_ESP_STORAGE_HOST_RELATIVE_SOURCES
    ports/esp-idf/storage/host/esp_storage_host_media.c
)

set(NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES
    ${NINLIL_ESP_STORAGE_MODEL_RELATIVE_SOURCES}
    ports/esp-idf/storage/esp/esp_storage_flash_media.c
)

set(NINLIL_ESP_STORAGE_HOST_TEST_RELATIVE_SOURCES
    ${NINLIL_ESP_STORAGE_MODEL_RELATIVE_SOURCES}
    ${NINLIL_ESP_STORAGE_HOST_RELATIVE_SOURCES}
    ports/esp-idf/storage/esp/esp_storage_flash_media.c
)
