get_filename_component(NINLIL_WIFI_HIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

idf_component_register(
    SRCS
        "main.c"
        "wifi_hil_provision.c"
        "wifi_hil_m4.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS
        "${NINLIL_WIFI_HIL_REPO_ROOT}/src/transport/wifi_v1"
        "${NINLIL_WIFI_HIL_REPO_ROOT}/src/transport/fabric_v1"
        "${NINLIL_WIFI_HIL_REPO_ROOT}/src/radio"
        "${NINLIL_WIFI_HIL_REPO_ROOT}/ports/esp-idf/src"
    REQUIRES ninlil
    PRIV_REQUIRES freertos nvs_flash esp_wifi esp_event esp_netif
)

target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wvla
    -fstack-usage
    -Wframe-larger-than=8192
)
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    NINLIL_ENABLE_PRIVATE_WIFI_V1=1
    NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
)
