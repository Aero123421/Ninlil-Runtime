# V1 LAB N6 owner bounded independent review

状態: **GO — P0=0 / P1=0 / P2=0**

- Date: 2026-08-03
- Subject: ADR-0036 private binding-to-N6 owner candidate
- Reviewer role: bounded independent code/specification review; no repository edits

## Verdict

GO for the reviewed V1 LAB owner boundary. This is not an ADR-0036 acceptance
or a physical-HIL completion claim.

The owner is the sole production caller of the accepted N6 identity,
authority and fresh-install entries. A partial install failure, including
`COMMIT_UNKNOWN`, shuts down N6 and invalidates previously issued keys and
handles. The owner also zeroizes its copied providers and identities.

An independent test oracle covers Controller A/B by local endpoint A/B, both
flows and both Hop/E2E layers. It derives the expected R7 binding and key
material independently of the owner implementation and checks the resulting
TX/RX leases.

## Evidence

- Normal and ASan/UBSan owner, accepted-adapter, codec and callsite tests pass.
- ESP-IDF component packaging and N6 storage/stack gates pass.
- The complete normal suite reached 422/426 on the first parallel run. The
  four failures were a stale private-source inventory, a registry self-test
  race and two build-type stack-gate mismatches; after the bounded fixes and
  canonical `RelWithDebInfo` configuration, all five affected/relevant tests
  pass.
- Physical USB/SX1262 HIL remains `NOT_RUN`.
