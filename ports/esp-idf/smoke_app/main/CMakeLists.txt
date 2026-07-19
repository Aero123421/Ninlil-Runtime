get_filename_component(NINLIL_SMOKE_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS
        "${NINLIL_SMOKE_REPO_ROOT}/src/radio"
        "${NINLIL_SMOKE_REPO_ROOT}/ports/esp-idf/src"
    REQUIRES ninlil
    PRIV_REQUIRES esp_timer freertos
)

# Ensure ISR timer dispatch is available for real from_isr path.
