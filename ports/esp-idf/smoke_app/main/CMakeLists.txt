idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ninlil
    PRIV_REQUIRES esp_timer freertos
)

# Ensure ISR timer dispatch is available for real from_isr path.
