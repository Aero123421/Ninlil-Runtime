get_filename_component(NINLIL_RADIO_HIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

# Private composition headers (R1/R2/R5/R9 + phy + domain SHA-256 + R7).
# Not public include/ninlil ABI.
set(NINLIL_RADIO_HIL_PRIV_INCLUDES
    "${NINLIL_RADIO_HIL_REPO_ROOT}/src/radio"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/src/model"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/src/transport"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/src/transport/fabric_v1"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/drivers/sx126x"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/ports/esp-idf/src"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/ports/esp-idf/include"
    "${NINLIL_RADIO_HIL_REPO_ROOT}/ports/esp-idf/storage/include"
)

idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS ${NINLIL_RADIO_HIL_PRIV_INCLUDES}
    REQUIRES ninlil nvs_flash driver esp_timer
)

# Stack-usage + frame ceiling on radio_hil composition (PCP/R5 path).
target_compile_options(${COMPONENT_LIB} PRIVATE
    -fstack-usage
    -Wframe-larger-than=4096
)
# V1 release HIL: PRODUCTION_BUILD always when session DIAG is off.
# Session RAM ledger is a separate diagnostic-only profile (not release evidence).
if(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
    message(WARNING
        "radio_hil SESSION_LEDGER_DIAG enabled: not a V1 release HIL profile "
        "(flash FULL fail-closed + evidence path require DIAG off)")
else()
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_SX1262_PRODUCTION_BUILD=1
    )
endif()
