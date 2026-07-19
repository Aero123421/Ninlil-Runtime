# Single authority for R7 production-private crypto sources (docs/31).
#
# Portable validation/nonce sources are shared by Host and ESP-IDF. Primitive
# adapters are mutually exclusive: OpenSSL 3 is Host-only; mbedTLS is ESP-only.
# Do not append platform adapters to NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES;
# each platform expands only its own adapter list.

set(NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES
    src/radio/r7_crypto_portable.c
    src/radio/r7_crypto_nonce.c
)

set(NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES
    src/radio/r7_crypto_openssl3.c
)

set(NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES
    ports/esp-idf/src/r7_crypto_mbedtls.c
)
