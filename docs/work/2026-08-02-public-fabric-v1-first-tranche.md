# Public Fabric v1 first tranche

Date: 2026-08-02
Normative authority: [ADR-0029](../adr/0029-v1-lean-public-composition.md)
Scope: portable public Fabric only; later Wi-Fi/USB/composition/ESP/HIL tranches excluded

## Outcome

- Added installed public `ninlil/fabric_v1.h` with the accepted opaque/value
  types, closed catalogs/bounds and exact 19-function allowlist.
- Kept one compiled source for every public value layout: the private candidate
  header now aliases the public types/status values, and the existing private
  tests continue to use their accepted symbol names.
- Added a thin one-to-one public wrapper over the accepted private core. No
  codec, projection, workspace proof, dispatch/trigger release, hash or test
  helper is declared in the public header.
- Added installable static `Ninlil::fabric_v1`. Its exported include surface is
  only the installed public include root; no `src/**` include root is exported.
- Added a clean tests-OFF installed consumer. It creates two separate Runtime /
  Fabric pairs and uses only installed Ninlil headers/targets for the real
  forward ApplicationData and reverse VERIFIED Receipt path.
- Documented the public packet-link provider contract: callback re-entry is
  forbidden, packet/permit borrows end at `start_send`, RF permits are
  independently validated and consumed once, retained sends are copy-owned,
  token/receive loans have exactly-once release, and close/destroy are drained.
- Extended the existing ABI manifest authority with all 61 Fabric constants,
  all 10 public value types, their 133 fields, and explicit size/alignment/
  offset coverage. The combined authority now covers 344 constants, 63
  structures and 665 fields.

The consumer uses separate consumer-owned storage instances for Runtime and
Fabric. This is intentional: its bounded memory provider supports one live
handle, while the public ABI permits independently provisioned providers. It
also proves the two Fabric instances do not share mutable singleton state.

## Focused acceptance ownership

| Behavior | Evidence |
| --- | --- |
| exact wrapper/catalog/workspace mapping | `fabric_v1_public_api` |
| wrong-thread zero mutation/I/O | `fabric_v1_public_behavior`, existing `fabric_v1_lifecycle` |
| provider-callback re-entry zero mutation/I/O | `fabric_v1_public_behavior` |
| bounded close and no provider callback after done | `fabric_v1_public_behavior`, existing lifecycle drain cases |
| loss/backpressure never synthesize success | existing `fabric_v1_lifecycle`, `fabric_v1_host_acceptance` |
| restart/uncertain-send fence | existing Fabric lifecycle restart/CU cases |
| duplicate invokes Application once | existing Runtime/Fabric multi-service actual E2E |
| installed two-instance forward/reverse happy path | `fabric_v1_tests_off_installed_consumer` |

The negative cases remain focused module tests instead of being copied into the
installed consumer executable.

## Manifest reconciliation

`fabric_v1` alone is recorded as `PACKAGE_EXPERIMENTAL`: the Host static archive,
installed header and installed consumer exist. ADR-0029 and its specification
re-review are the authority for this first tranche. The broader ADR-0028 module
framework remains future work, so no absent ESP package metadata, cross-module
dependency, immutable receipt or reviewer/commit provenance was invented.

The manifest exception is exact to this module, this state, these two
acceptance IDs and this work record. It cannot promote Fabric to
`RELEASE_SUPPORTED`; that future transition must satisfy the ordinary strict
promotion/evidence path. The other seven planned modules remain private/future.

The ADR-0029 specification re-review and the focused first-tranche
[implementation re-review](../reviews/2026-08-02-public-fabric-v1-first-tranche-rereview.md)
are GO with P0/P1/P2 all zero. This is a Host experimental-package milestone;
it does **not** claim a release-ready package, Wi-Fi/USB/ESP support, HIL or
physical-radio completion.

## Verification recorded in this worktree

| Check | Result |
| --- | --- |
| tests-OFF strict Fabric/Runtime build and install | PASS |
| `fabric_v1_tests_off_installed_consumer` | PASS (1/1) |
| `fabric_v1_public_api` | PASS (1/1) |
| `fabric_v1_public_behavior` | PASS (1/1) |
| `abi_contract_header` | PASS (1/1) |
| `abi_contract_output` | PASS (1/1) |
| `abi_contract_enum` | PASS (1/1) |
| `abi_manifest_repeatable` | PASS (1/1) |
| `abi_manifest_golden` | PASS (1/1) |
| `abi_manifest_coverage` | PASS (1/1) |
| `abi_drift_check` + `abi_drift_negative` | PASS (2/2) |
| `smoke_c11` + `smoke_cxx17` | PASS (2/2) |
| `self_contained_fabric_v1_c11` | PASS (1/1) |
| `self_contained_fabric_v1_cxx17` | PASS (1/1) |
| fresh strict normal focused suite | PASS (15/15) |
| existing `fabric_v1_lifecycle` + `fabric_v1_host_acceptance` | PASS (2/2) |
| fresh ASan/UBSan: installed consumer + public API/behavior | PASS (3/3) |
| private-feature Runtime/Fabric actual E2E regression | PASS (1/1) |
| final repair-focused normal suite | PASS (7/7) |
| final independent implementation re-review | GO (P0=0 / P1=0 / P2=0) |
| physical Wi-Fi/USB/SX1262/ESP32-S3 HIL | NOT_RUN — later ADR-0029 tranches |
