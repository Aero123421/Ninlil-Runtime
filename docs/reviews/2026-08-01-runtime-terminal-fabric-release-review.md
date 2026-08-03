# Runtime terminal / Fabric release milestone review

- Date: 2026-08-01
- Scope: ADR-0032 terminal owner projection and transaction-level Fabric release
- Final result: **GO — P0=0 / P1=0 / P2=0**

## Reviewed boundary

- Runtime projects one durable terminal owner as a full transaction ID and a
  deterministic non-zero release token.
- The projection is RAM-only and invokes no Port callback. The composition
  owner is responsible for owner-thread and re-entry validation before use.
- Fabric preflights every matching FBA1 and FBT1 row by full transaction ID.
  A different non-zero token rejects the call before any mutation.
- One call performs at most one durable transition. Provider tokens remain
  owned and drained by the existing bounded Fabric step.
- Same-token replay and cold-restart commit-unknown classification are
  idempotent; private symbols are not installed as public API.

## Review history

The first review returned NO-GO with one P1 and one P2:

1. the projection used the Execution Port for owner validation despite its
   no-Port contract;
2. the conflict test did not place an actionable zero-token row before a later
   row carrying a different token.

The implementation removed the Port call and documented the caller precondition.
The focused regression now proves that the later conflicting token leaves
Storage calls, durable data, Fabric RAM, and provider state unchanged. A second
review closed both findings.

## Verification

- normal focused and Fabric regression: 16/16 passed;
- ASan/UBSan focused and Fabric regression: 16/16 passed;
- tracked-file whitespace check: passed.

This review does not claim the public `composition_v1` owner, sidecar wiring,
ESP target integration, or physical HIL complete.
