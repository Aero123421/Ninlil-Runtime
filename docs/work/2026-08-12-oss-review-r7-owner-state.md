# OSS review: R7 issue-pipeline owner state

Date: 2026-08-12

## Scope

This tranche closes the R7 portion of OR-21 named by the 2026-08-11 OSS
review. The private NRW1 issue coordinator and checked-issue adapter no longer
store volatile work state in mutable process globals.

| Former state | Resolution |
| --- | --- |
| `g_slots[8]` and `g_in_api` in `r7_frag_issue_coordinator.c` | Moved into caller-owned `ninlil_r7_frag_issue_coordinator_t`. Related candidates within one L1 coordinator domain share this owner and retain the exact eight-reference bound. |
| Default R5 registry and lazy-init flag in `r7_frag_checked_issue.c` | Moved into the owning production bind/orchestrator registry. The checked-issue path now requires an explicit caller-owned registry and has no process-static fallback. |
| R5 whole-path `g_r5_in_api` | Moved into the same registry owner; same-owner checked-issue or activation reentry rejects before authority mutation. |
| Activation snapshot/token replay values | Moved into the registry owner. Snapshot replay and issuer-token continuity remain owner-local for that owner's lifetime. |

`ninlil_r7_frag_prod_bind_t` and the smaller private adapter orchestrator embed
their own coordinator and registry state. Existing optional explicit R5
registry binding remains available. Reset/reinit wipes the embedded state;
standalone coordinator/registry owners have explicit init/fini functions.

## Invariants

- The Normative docs/30 FIFO contract remains eight issued Permit references
  within one caller-owned L1 coordinator domain. Different Runtime/Cell owners
  do not share bytes; candidates governed by the same coordinator still share
  one FIFO.
- Permit ordering, duplicate detection, hold/resume, authority-wide cleanup,
  typed issue results, activation single-use behavior, and R1/R2 cleanup order
  are unchanged.
- `ninlil_r7_frag_issue_coordinator_fini` and
  `ninlil_r7_r5_issue_registry_fini` overwrite every byte of their owner
  objects. Registry row clear intentionally retains activation replay identity
  until owner teardown.
- No installed/public header, public symbol, ABI value, wire byte, storage key,
  storage encoding, feature default, or promotion state changed. All changed C
  interfaces are private and non-installed.

## Verification

- Focused two-owner/reentry/zeroization proof:
  `r7_issue_owner_state: 23 checks, 0 failures` in both normal and ASan/UBSan
  builds. It interleaves two coordinator owners with the same authority,
  sequence, and digest; proves one owner's busy guard cannot block or mutate
  the other; checks registry and activation isolation; checks same-owner
  coordinator, checked-issue, and activation reentry rejection; and compares
  every owner byte with zero after fini.
- Full private R7/NRW1 suite: **17/17 PASS** in the normal profile and
  **17/17 PASS** in the ASan/UBSan profile. This includes production
  integration, radio packet-link vertical, wire fixture, lifecycle, target
  smoke, and stack gates.
- `radio_wire_r6_docs_gate.py check`: PASS after the caller-owned coordinator
  contract was added to docs/30.
- Source and archive scans find none of the removed `g_slots`, `g_in_api`,
  `g_r5_issue_*`, or `g_activate_*` symbols. `git diff --check`: PASS.

## Nonclaims

This closes the private R7 coordinator/checked-issue mutable-state finding, not
physical RF/HIL, ESP device execution, regulatory approval, or promotion of the
default-OFF private R7 feature. It does not change the separate static buffers
used only by the deterministic target-smoke program, which are target-owned
test/smoke storage rather than cross-instance issue-pipeline state.
