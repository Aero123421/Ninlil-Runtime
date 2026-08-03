# MFDT exact-one attempt ordering 3C1

Date: 2026-08-02  
Status: **exact-one attempt ordering implemented and targeted GREEN**

## Claims

- MFDT exact-one public admission selects the Application attempt only after the
  transaction ID and canonical one-target roster are fixed, and before NTS3 encode,
  Foundation storage begin, or sidecar mutation.
- Selection uses at most four `entropy.fill(16)` draws. Port failure/partial output,
  all-zero output, and collision with every live/restored in-use Foundation
  transaction attempt ID each consume one draw; exhaustion returns
  `NINLIL_E_ENTROPY`.
- The candidate is projected into the scratch admission with the existing normal
  prepare semantics: transaction and target attempt IDs/prepared state, attempt
  index/target index, counters, and budgets. It becomes public/durable Foundation
  truth only in the existing one admission FULL.
- The target attempt is non-zero and byte-identical in Foundation transaction state,
  target state, and NM3S `TRANSFER_OPEN.original_attempt_id`. The existing MFDT
  transfer ID remains byte-identical between the Foundation NTS3 target correlation
  and NM3S/OPEN.
- Existing exact-one sidecar pre-arm remains before Foundation FULL. Entropy
  exhaustion performs zero Foundation put/erase/commit, zero sidecar active arm,
  zero Bearer wire send, zero TxGate acquire, and zero Application callback.
- Ordinary payloads through 926 bytes retain the existing single-frame route.

## Verification

Normal and ASan/UBSan builds both passed:

```text
v1_runtime_capability                                      1/1 PASS
ctest -R 'mfdt|multi_frame'                               41/41 PASS
Foundation codec/durable/restart focused set               9/9 PASS
```

The deterministic entropy fixture covers partial-output then success and four
all-zero draws ending in `NINLIL_E_ENTROPY` with the zero-mutation assertions above.

Baseline-equal failure: `runtime_lifecycle_model` still fails only at
`runtime_lifecycle_model_test.c:1098` in both normal and ASan/UBSan builds. This is
the same shared-worktree failure recorded before 3C1 and is outside this tranche.

## Nonclaims

3C1 does not implement or claim multi-target MFDT admission, restart/orphan
reconciliation, arm cleanup/disarm, READY or Application handoff/Receipt, a public
MFDT API, a new table/state/kind/schema, default-ON/release support, or ESP/HIL
completion. Existing post-pre-arm Foundation failure fencing remains unchanged for
later 3C2 work.
