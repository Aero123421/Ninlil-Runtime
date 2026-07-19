# Single authority for R7 T1 production-private NRW1 SINGLE wire codec sources
# (docs/32, ADR-0012).
#
# Portable pure codec is shared by Host and ESP-IDF. No platform crypto adapter:
# T1 uses T0 ninlil_r7_crypto_* only. Do not append this list into public libs
# or install rules. Do not inject test/oracle/generated fixtures here.

set(NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES
    src/radio/r7_wire_codec.c
)
