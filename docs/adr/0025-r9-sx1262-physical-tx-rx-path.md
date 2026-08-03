# ADR-0025: R9 SX1262 Physical TX/RX Path (permit sole edge)

- Status: **Proposed** (implementation candidate; not Accepted Normative freeze)
- Date: 2026-07-29
- Relates: ADR-0008 / docs/28 (R4 control-plane; **not superseded**), ADR-0004 / docs/24 (permit authority), docs/23 §10.2 R9, radio_hal R1

## Context

Accepted **ADR-0008 / docs/28** freeze R4 as **reset/init/SPI control-plane only**: production `request_transmit` is explicit **TX_DENIED**, SetTx/SetRx are banlisted, and structural gates forbid RF emission opcodes in the R4 control-plane TU.

Roadmap **R9** requires the SX1262 physical TX path to be reachable **only after** Physical Compliance Permit validate+consume (sole edge), with host deterministic fake-bus proof and ESP composition for later HIL — **without** claiming RF HIL PASS or legal certification.

Changing Accepted R4 semantics “to make TX work” would be incorrect. R9 is a **new production-private slice** with explicit opt-in, separate source authority, and fail-closed defaults.

## Decision

1. **R4 remains immutable for its TU:** `drivers/sx126x/ninlil_sx1262_backend.c` continues default-deny bare `ninlil_sx1262_request_transmit` with zero SetTx SPI. R4 gates and deny string stay.
2. **R9 physical path is a separate production-private module** (`ninlil_sx1262_phy.*` + `src/radio/sx1262_r9_edge.*`), packaged with runtime private sources; host R9 suite and ESP `radio_hil_app` compose it.
3. **Sole production TX edge (exact order):**  
   sealed frame → `ninlil_radio_hal_transmit_with_permit` (R1: live bind + digest + R2 validate/consume + sequence/single-use watermark sole authority) → `sx1262_r9_edge` (SHA-256 recompute + constant-time digest compare; independent R3 airtime recompute; RF profile/channel; SetTx RTC timeout units) → `ninlil_sx1262_phy_arm_tx` (**sole SetTx SPI issuer**).  
   Bare `request_transmit` never arms RF.  
   Legacy `ninlil_sx1262_request_transmit_with_permit` is **absent under `NINLIL_SX1262_PRODUCTION_BUILD`** (ESP/HIL); host fixtures only.
4. **ESP SPI dual-mode (R4 not weakened):** default bus capability is **CONTROL_ONLY** (R4 closed allowlist; RF banlist denied at SPI). Single-shot private `bus_grant_rf_sole_capability` opens **RF_SOLE** (R4 allowlist ∪ closed R9 physical opcode set). Production call-site gate enforces exactly one grant site (`radio_hil_app`). Pure policy: `sx1262_rf_bus_capability_logic`.
5. **RX path:** continuous/scheduled RX with DIO1 ISR **latch only** (no SPI in ISR); single-owner task poll/IRQ read + BUSY + monotonic deadlines; stale generation rejection; no heap/VLA.
6. **Board profile (Kconfig defaults):** NSS=41, SCK=7, MOSI=9, MISO=8, RST=42, BUSY=40, DIO1=39, ANT_SW=38, ANT active-high. Portable layer holds only opaque pin ids and RF profile numbers.
7. **Nonclaims:** no RF HIL PASS, no Japan legal certification, no public `include/ninlil` ABI, no R4 complete redefinition, no Accepted Normative rewrite until evidence is complete. **Status remains Proposed** until host gates + ESP ELF/map resource evidence + (when available) RF HIL close the acceptance criteria.

## Consequences

- Host fake-bus golden tests + ASan for R9 module.
- ESP `radio_hil_app` composition builds the production driver for serial machine-readable control; hardware RF evidence remains out of scope.
- R4 CTest/gates continue to pass with PHY default OFF.

## Open / stop slices

- Exact Japan channel/power tables remain R2/R5 authority; R9 validates **caller-supplied closed profile bounds** only.
- Full IRQ coalescing on multi-core ESP is composition-owned; portable phy uses bus ops samples only.
