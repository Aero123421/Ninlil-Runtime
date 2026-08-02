# Runtime composition v1 specification review

Date: 2026-08-01  
Reviewer: independent Codex review-only agent  
Decision: **GO — P0=0 / P1=0 / P2=0**

## Scope

The review compared ADR-0032 with ADR-0029, the installed Runtime, Fabric and
POSIX port APIs, and the existing private MFDT, FRAG and RRMP ownership paths.
It reviewed specification feasibility only; no implementation or physical HIL
claim was accepted.

## Findings closed before GO

- Fabric PathPolicy and AuthorityBinding now have an exact internal
  route/parent projection. No raw route or parent API is published.
- MFDT remains owned solely by Runtime step. The shared reliability budget has
  an exact closed owner set, split and call order, so work is not advanced
  twice.
- Close rejects live external registrations without mutation and retains a
  Runtime `COMMIT_UNKNOWN` result while bounded reverse-order drain continues.
- Deterministic domain namespaces isolate two Runtime IDs using the same
  Storage provider and remain stable across restart.

## Overengineering check

The accepted surface remains one opaque owner, two bounded step value types
and eight functions in `Ninlil::runtime`. It adds no plugin framework, public
MFDT/FRAG/RRMP state machine, new application model, wire format or storage
schema.

## Terminal release amendment

The terminal-release clarification was independently re-reviewed with
**P0=0 / P1=0 / P2=0**. Profile 1 uses a deterministic non-zero projection of
the full transaction ID only as an equality fence after the full ID matches.
Runtime projects one durable terminal owner rather than reconstructing attempt
history; Fabric then preflights every matching bounded FBA1/FBT1 row and
persists at most one release transition per call. This covers summarized
EventFact retry cycles and inbound owners without adding a Runtime storage
field. A zero remaining Fabric budget skips the existing Fabric step.

Implementation, installed public-only acceptance, ESP-IDF integration and
physical USB/Wi-Fi/SX1262 tests remain separate work. Physical cases are
`NOT_RUN` until executed with hardware.
