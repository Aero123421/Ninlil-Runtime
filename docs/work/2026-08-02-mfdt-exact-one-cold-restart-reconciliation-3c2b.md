# MFDT exact-one cold-restart reconciliation 3C2b

Date: 2026-08-02
Status: **bounded sender reconciliation implemented and targeted GREEN**

## Claims

- After Foundation recovery, the private MFDT owner recovers the sidecar and
  classifies the complete bounded inventory before readiness or cleanup.
  One to four independent exact-one nonterminal Foundation transactions are
  matched 1:1 to sender `NM3S+NRC1` rows by transfer ID.
- A match is accepted only after the existing canonical OPEN encoder rebuilds
  the expected OPEN, entries, and whole-content digest from the recovered
  Foundation transaction and compares them byte-for-byte with the sidecar.
  Session generation, durable peer, original transaction/attempt identity,
  target ordinal, Application identity, and content are therefore exact.
- Exact matches are rebound with the configured generation/cookie and their
  volatile Runtime Application bindings are reconstructed. Cold send resumes
  the same Foundation attempt and transfer ID; the OPEN body is byte-identical.
  Reconciliation itself draws no entropy, sends no wire frame, acquires no
  TxGate permit, and invokes no Application callback.
- An unmatched sender row is cleanup-eligible only when it is the exact fresh
  one-FULL OPEN arm and its OPEN origin transaction ID is wholly absent from
  Foundation. A terminal or non-MFDT Foundation row with that same origin is
  incompatible truth and fences before mutation.
- Cold orphan cleanup has a private unbound-recovered entry point. It preserves
  the stricter live 3C2a ownership predicate, reuses the same transaction-local
  byte-compare/erase core, and never reissues OPEN or charges a retry. Up to
  four already-classified fresh orphans are removed sequentially.
- Cleanup definite failure returns `NINLIL_E_STORAGE`; cleanup
  `COMMIT_UNKNOWN` returns `NINLIL_E_STORAGE_COMMIT_UNKNOWN`. Both fence and
  publish no ready owner. Receiver active rows, same-ID metadata/content
  mismatch, nonfresh rows, and terminal/non-MFDT same-origin truth fence before
  sidecar mutation.
- Valid retained Host terminal catalog rows remain recoverable. A terminal
  Foundation history without a corresponding active sidecar row does not by
  itself block startup.

## Acceptance coverage

- one exact cold restart: same transaction, attempt, transfer ID, and OPEN body;
- four independent exact-one transactions at the Host upper bound;
- Foundation-absent fresh orphan cleanup success;
- orphan cleanup definite I/O failure and CU-OLD;
- content mismatch, terminal same-origin, non-MFDT same-origin, and valid
  receiver active row, all mutation-free before the corruption fence;
- existing private direct-open restart tests now assert the same Foundation-
  absent orphan authority rather than claiming sidecar-only resume.

## Verification

Normal and ASan/UBSan runs passed:

```text
v1_runtime_capability                                      PASS / PASS
mfdt_v1_host_coordinator_acceptance_private                PASS / PASS
ctest -R 'mfdt|multi_frame'                               41/41 / 41/41 PASS
Foundation codec/durable/restart focused set                9/9 / 9/9 PASS
MFDT-OFF v1_runtime_capability build/run                         PASS
git diff --check                                               PASS
```

## Nonclaims

3C2b does not add a public API, durable schema/table/state, process-global
owner, or unbounded work. It does not claim one-transaction multi-target
restart, receiver resume/publication/handoff, default-ON or release promotion,
ESP completion, or HIL evidence. The current late private configure seam
remains test-only; production composition still must place the same reconcile
before Bearer open/public dispatch.
