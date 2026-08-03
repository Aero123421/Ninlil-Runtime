# Single source authority for private NRW1 LINK/FRAG candidate (docs/30, ADR-0010).
#
# Host and ESP-IDF expand these exact lists when the default-OFF enable option is
# on. Do not file(GLOB). Do not install. Do not append into public/installed
# libs. Do not inject test/oracle fixtures into the production list.
#
# Enable contracts:
#   Host:  NINLIL_ENABLE_R7_FRAG_PRIVATE=ON (top-level CMake option, default OFF)
#   ESP:   CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE=y (component Kconfig, default n)
#
# Source closure (DRAM / production claim):
#   PRODUCTION — may land in ESP component when Kconfig ON.
#     No test-durable simulator, no multi-session lab BSS.
#     target_smoke builds LIGHT under ENDPOINT (one reasm engine, no sess).
#   LAB — host private lib / unit tests only.
#     session + durable crash simulator. Must not enter ESP component.
#
# When disabled: zero FRAG TUs in component archive / public install / default
# smoke ELF (symbol absence is a packaging gate).
# When enabled on ESP: PRODUCTION only + ENDPOINT + no test durable.
# Concurrent production instance budget (ENDPOINT cell): 1 reasm engine
# (2 slots), 1 bind pair, caller-owned matrix_ws/xfer — no static multi-sess.

# Production planner / wire / orch (depends on r7_crypto_* + N6/R2/R1 for orch).
set(NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES
    src/radio/r7_frag/r7_frag_state.c
    src/radio/r7_frag/r7_frag_wire.c
    src/radio/r7_frag/r7_frag_core.c
    src/radio/r7_frag/r7_frag_ack_ledger.c
    src/radio/r7_frag/r7_frag_checked_issue.c
    src/radio/r7_frag/r7_frag_issue_coordinator.c
    src/radio/r7_frag/r7_frag_adapters.c
    src/radio/r7_frag/r7_r2_authority_clock.c
    src/radio/r7_frag/r7_frag_prod_orch.c
    src/radio/r7_frag/r7_frag_target_smoke.c
)

# Lab/host-only: test durable simulator + integrated session (not production N6).
set(NINLIL_R7_FRAG_LAB_RELATIVE_SOURCES
    src/radio/r7_frag/r7_frag_durable.c
    src/radio/r7_frag/r7_frag_session.c
)

# Full portable private set (host private lib + host tests).
set(NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES
    ${NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES}
    ${NINLIL_R7_FRAG_LAB_RELATIVE_SOURCES}
)

# Guard: authority file must not be confused with test registration.
set(NINLIL_R7_FRAG_SOURCES_AUTHORITY_LOADED TRUE)
