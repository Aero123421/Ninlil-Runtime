# MFDT exact-one definite-Failure cleanup 3C2a

Date: 2026-08-02  
Status: **post-pre-arm definite-Failure cleanup implemented and targeted GREEN**

## Claims

- The private Host coordinator can disarm only one exact, freshly opened
  sender arm identified by Host slot and transfer ID. It requires a started,
  recovered, inventory-certain owner; an occupied/bound/active/durable sender
  descriptor; exactly one sender FULL; an active packed `OPEN_PENDING` engine;
  and an owned outstanding OPEN in `WAIT_OPEN_ACC` with no completion/abort.
- In one sidecar FULL, Host re-reads the exact `NM3S` and `NRC1` rows into
  caller-provided fixed scratch, byte-compares both with the current canonical
  slot images, then erases both. Wrong slot, transfer ID, freshness, or bytes
  erases zero rows.
- Only a cleanup commit `OK` decrements Host committed keys/logical bytes,
  tracked groups, and active count, then resets the slot. Definite cleanup
  failure and `COMMIT_UNKNOWN` publish no deletion or counter change; CU marks
  inventory uncertain under the existing Host rule.
- The Runtime-owner wrapper reuses its existing iterator scratch and clears the
  slot binding only after Host cleanup succeeds.
- After sidecar pre-arm, Foundation `COMMIT_UNKNOWN` retains the arm and fences
  without cleanup. A definite Foundation failure attempts cleanup: cleanup
  success returns the original Foundation status without a new fence; cleanup
  CU returns `NINLIL_E_STORAGE_COMMIT_UNKNOWN` and fences; definite cleanup
  failure returns its mapped failure and fences. All paths send zero wire
  frames, acquire zero TxGate permits, and invoke zero callbacks in admission.
- Foundation transaction/public admission counters, resource ledger, quota,
  and markers are published only after Foundation FULL `OK`. The definite
  Foundation I/O-error test proves they remain unchanged, sidecar active count
  returns to zero, and a later ordinary admission succeeds.

## Verification

Normal and ASan/UBSan targeted runs passed:

```text
v1_runtime_capability                                      1/1 PASS
mfdt_v1_host_coordinator_acceptance direct executable          PASS
ctest -R 'mfdt|multi_frame'                               41/41 PASS
Foundation codec/durable/restart focused set               9/9 PASS
git diff --check                                               PASS
```

Direct Host coverage includes exact pair erase/counter reset, wrong slot and
ID, nonfresh outbox ownership, same-transaction byte mismatch, definite commit
failure with a successful retry, and cleanup CU-OLD counter/inventory canaries.
Runtime coverage includes Foundation definite I/O failure, Foundation CU with
zero cleanup commits, definite cleanup failure, and cleanup CU without a false
clean result.

## Nonclaims

3C2a does not implement or claim restart/orphan reconciliation, multi-target
cleanup, candidate-exhaustion cleanup across earlier arms, Application
handoff/Receipt, a public API, a new schema/table/state, default-ON or release
support, or ESP/HIL completion. It does not infer Foundation success from
sidecar bytes or sidecar deletion from a cleanup CU.
