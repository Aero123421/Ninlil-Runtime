get_filename_component(NINLIL_SMOKE_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

set(NINLIL_SMOKE_PRIV_INCLUDES
    "${NINLIL_SMOKE_REPO_ROOT}/src/radio"
    "${NINLIL_SMOKE_REPO_ROOT}/ports/esp-idf/src"
    "${NINLIL_SMOKE_REPO_ROOT}/examples/multi_service_node"
)
# Private FRAG smoke headers only when Kconfig enables the candidate.
if(CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE)
    list(APPEND NINLIL_SMOKE_PRIV_INCLUDES
        "${NINLIL_SMOKE_REPO_ROOT}/src/radio/r7_frag"
    )
endif()
if(CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE)
    list(APPEND NINLIL_SMOKE_PRIV_INCLUDES
        "${NINLIL_SMOKE_REPO_ROOT}/src/runtime/mfdt_v1"
    )
endif()

idf_component_register(
    SRCS
        "main.c"
        "composition_public_target_smoke.c"
        "${NINLIL_SMOKE_REPO_ROOT}/examples/multi_service_node/multi_service_node_profile.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS ${NINLIL_SMOKE_PRIV_INCLUDES}
    REQUIRES ninlil
    PRIV_REQUIRES esp_timer freertos
)

set_source_files_properties("composition_public_target_smoke.c" PROPERTIES
    COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=2048"
)

# Ensure ISR timer dispatch is available for real from_isr path.
