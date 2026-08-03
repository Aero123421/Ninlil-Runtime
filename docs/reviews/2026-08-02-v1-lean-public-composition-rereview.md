# V1 lean public composition repair re-review

Date: 2026-08-02  
Reviewer: independent Codex Sol high, review-only  
Decision: **GO — P0=0 / P1=0 / P2=0**

ADR-0029 is accepted as the V1 public boundary. Implementation may begin with
the first `fabric_v1` tranche.

## Closed findings

- The future `composition_v1` owner has explicit responsibility, construction
  order, bounded stepping, restart fences and public-only acceptance paths.
  Its exact C contract is intentionally deferred to a later amendment, and
  that missing amendment or a private include blocks V1 completion.
- Fabric now has an exact public type/status/function allowlist, fixed bounds,
  workspace/ownership/lifetime rules, thread/re-entry behavior and close/
  destroy conditions. Private helper symbols remain excluded.
- Linux/macOS POSIX USB serial is an explicit tranche and Host USB is named in
  physical HIL.
- Duplicate, loss/backpressure, wrong-thread/re-entry, restart and close have
  observable acceptance outcomes. The installed consumer stays focused on the
  two-instance happy path; negative cases stay in module tests.

## Overengineering check

The review explicitly rejects adding the future `composition_v1` types during
the Fabric tranche. ADR-0028's eight-package promotion, a plugin framework and
raw MFDT/RRMP/FRAG APIs are not V1 requirements.
