# V1 LAB durable provisioner bounded independent review

状態: **GO — P0=0 / P1=0 / P2=0**

- Date: 2026-08-03
- Subject: ADR-0036 private durable LAB provisioner candidate
- Reviewer role: bounded independent code/specification review; no repository edits

## Verdict

GO for the reviewed provisioner tranche. This is not ADR-0036 acceptance,
NCG1 bridge completion or a physical-HIL claim.

The implementation keeps the cross-namespace order bounded and private:
`NLB1` floor scan, fresh `ninlil.n6.v1` reset, four N6 installs and exact
`NLB1` FULL publication. It adds no public API or general provisioning
framework.

## Findings closed during review

The first review found one P1 and one P2:

- `pair_generation == UINT32_MAX` could be persisted and create a floor that
  could never be advanced. It is now rejected before Storage or N6 mutation;
  the test also proves that N6 remains `INIT` and an existing 32-row namespace
  is unchanged.
- The final `NLB1` publication `COMMIT_UNKNOWN` path was not directly tested.
  The test now targets the commit after reset and four installs, for both
  hidden outcomes. It checks zero output handles, N6 shutdown, no live Storage
  handles, and the correct cold-restart floor of zero or one.

The final review found no new P0, P1 or P2. It also found no unnecessary
public boundary or excessive abstraction.

## Evidence

- Normal and ASan/UBSan provisioner tests pass.
- Owner, accepted-adapter, NVB1 and exact-binding tests pass.
- Exact 32-row reset, two-pair restart, global membership floor, fifth-floor
  fence, malformed boot and definite/unknown Storage failures are covered.
- The full normal build, private-source inventory, protocol-magic gates and
  ESP-IDF component packaging gates pass.
- A parallel-suite race between the magic-registry mutation self-test and the
  independent Production Attachment scanners is serialized; all six scanners
  pass together with `-j6`.
- The unrelated HIL-evidence self-test timing failure from that loaded run
  passes when rerun in isolation.
- Physical USB/SX1262 HIL remains `NOT_RUN`.
