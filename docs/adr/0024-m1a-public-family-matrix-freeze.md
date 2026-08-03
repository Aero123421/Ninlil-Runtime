# ADR-0024: M1a Public Application Family Matrix Freeze

- Status: **Accepted**
- Date: 2026-07-29
- Supersedes: none (refines docs/12 §4.1 / §14 and docs/14 M1a matrix without replacing them)

## Context

Independent Core audit observed a contradiction surface:

- **Accepted Normative** ([docs/12](../12-foundation-abi.md) §4.1 / §14, [docs/14](../14-foundation-ports-and-simulator.md)) freezes M1a public application families to **DesiredStateCommand** and **EventFact** only. Named reserved families `LATEST_STATE_RESERVED` / `MEASUREMENT_RESERVED` / `TRANSFER_RESERVED` / `CONFIG_RESERVED` / `NETWORK_CONTROL_RESERVED` must fail `service_register` with `NINLIL_E_UNSUPPORTED`.
- **LAB / B5** private family workspaces and historical scenario names still mention “LatestState” and similar product labels.
- `v1_direct_1hop_e2e` scenario 7 (“LatestState”) registered as EventFact (correct M1a family) but submitted with LatestState-shaped identity (`generation != 0`, zero `event_id`), producing API `INVALID_ARGUMENT` and an invalid/zero result kind.

The V1 generic product narrative (display occupancy, measurement, transfer, config) must not silently enable reserved public families without a Normative + Accepted ADR that unfreezes them.

## Decision

1. **Single public authority for M1a / V1-LAB Foundation Core:** docs/12 and docs/14. Public `service_register` admits **only**:
   - `NINLIL_FAMILY_DESIRED_STATE` (downlink Command)
   - `NINLIL_FAMILY_EVENT_FACT` (uplink EventFact)
2. **Named reserved families remain public-red:** register = `NINLIL_E_UNSUPPORTED`, no public submit path, no silent coercion of reserved enum values into DS/EF.
3. **Product “LatestState” / display uplink under M1a** is modeled as **EventFact** (non-zero `event_id`, `generation == 0`, `NINLIL_NO_DEADLINE`, content digest = SHA-256(payload)). Historical test/example names may say “latest_state” but the **family enum and submission identity must be EventFact**.
4. **Private B5 family workspaces** (`runtime_v1_family_capability.c` generation/stale helpers, measurement retention, transfer/config scopes) remain **internal / unit-test only**. They are not a public registration or admission authority and do not authorize enabling reserved families on the public ABI.
5. **Measurement / Transfer / Config public enablement is out of scope** for this ADR. Enabling any reserved family publicly requires a new Accepted ADR that updates docs/12 §14, docs/14 matrix, ABI versioning if needed, and full positive/negative/restart/ASan evidence. Until then those families stay UNSUPPORTED at register.

## Consequences

- Scenario 7 and display loopback examples use EventFact identity and must go green under normal + ASan.
- Public register tests for all named reserved families remain RED (`UNSUPPORTED`).
- No contradiction: product label “latest state display” ≠ public family enum `LATEST_STATE_RESERVED`.
- Future V1 SDK expansion of LatestState as a first-class public family is a deliberate Normative unfreeze, not a LAB shortcut.

## Non-claims

- Does not claim MeasurementBatch, BoundedTransfer, ConfigRevision, or LatestState as public M1a families.
- Does not claim D3/D4 domain completeness or production field support.
- Does not change public C ABI symbols or enum numeric values.
