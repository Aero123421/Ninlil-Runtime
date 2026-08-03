# FBA1 permit colocation specification sync

Date: 2026-07-29  
Scope: ADR-0017/0018 machine authority and Normative documentation  
Status: software specification/generator sync; physical HIL **NOT_RUN**

## Reason

The earlier separate durable permit-claim record made the published
`273`-record profile and the implementation's bounded `64`-attempt model
inconsistent. The permit claim is now part of the same FBA1 attempt record.

## Closed decisions

- FBA1 payload/value are exactly `688 / 712` bytes.
- Payload offsets are `permit_id[16] @660`,
  `permit_expires_at_ms u64 @676`, and `permit_claim_state u32 @684`.
- Existing `retry_lifetime_clock_epoch_id` is also the permit clock authority.
- Provider I/O requires a same-FBA1 `CLEAR -> CLAIMED` FULL replacement first.
- Definite non-accept changes state and clears the claim in one same-FBA1 FULL
  replacement. RETAINED or uncertain outcomes keep `CLAIMED`.
- RETRYABLE re-entry requires a fresh, never-reissued
  `(clock_epoch_id, permit_id)` pair.
- GC requires DRAINED plus Runtime release and either an old permit epoch, or
  the same trusted epoch with
  `now >= max(retention_until, permit_expires_at)`. One attempted erase is one
  step work item.
- Installed/public ABI and NFL1/NWB1 wire are unchanged.

## Exact profile arithmetic

- Workspace: `198,656` bytes.
- Attempt region: `52,224 = 64 x 816` bytes.
- Durable rows: `273`.
- Committed key+value bytes: `133,572`.
- Foundation Storage CU bytes: `137,940`.
- FULL staging: `546` rows / `275,880` CU bytes.

## Authorities synchronized

- `tools/fabric_bearer_spec_vector_gen.py`
- `tools/fabric_bearer_spec_gate.py` (independent Python and embedded Node)
- `spec/vectors/fabric-bearer-spec-v1.json`
- generated Fabric C fixtures
- ADR-0017, ADR-0018, and compatibility summary

Physical ESP/AP/radio HIL was not performed by this documentation/vector
tranche and remains explicitly **NOT_RUN**.
