idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS "../../storage/private"
    REQUIRES ninlil mbedtls
)
