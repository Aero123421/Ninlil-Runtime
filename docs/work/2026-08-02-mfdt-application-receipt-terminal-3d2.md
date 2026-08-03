# MFDT Application Receipt and receiver terminalization 3D2

Date: 2026-08-02  
Status: **Host software verified / 3D2 complete**

## Implementation contract

- Advance only a positive Foundation evidence FULL whose durable stage meets
  the original OPEN `required_evidence`. Derive the source-private streaming
  SHA-256 over the exact ADR-0021 Application-evidence preimage, including the
  private publication token, original transaction/attempt, ordinal, stage,
  exact evidence length, and evidence bytes.
- Commit that token/digest through the existing Host receiver publication
  handoff. Exact replay is a no-op; mismatch or `COMMIT_UNKNOWN` fails closed
  before later callback, Receipt, wire, or mutation.
- Only after durable handoff COMPLETE, reconstruct the original Application
  envelope from OPEN and resume the existing Foundation Application Receipt
  path. Do not duplicate Receipt encoding, send, retry, or closure logic.
- Only after the Foundation reverse Receipt is durably closed may the existing
  MFDT receiver terminal/retention path erase active content. Cold recovery
  uses durable handoff, Foundation closure, and exact terminal correlation;
  volatile carrier binding is never Application or terminal authority.
- Restart resumes at the first incomplete boundary: evidence to handoff,
  handoff to Receipt, Receipt closure to terminal/release, or exact retained
  terminal no-op. Identity, digest, transfer, ordinal, state, or terminal
  mismatch is storage corruption and fences all later work.
- Preserve Runtime transition/send budgets and the existing Foundation-before-
  MFDT ordering. A definite failure retains the current retry contract; every
  `COMMIT_UNKNOWN` fences until cold classification.

## Verification boundary

Reuse the existing 927/4096/32768-byte 3D1 table. Positive 927 and 32768-byte
rows progress through handoff, Receipt closure, terminalization, and release;
the 4096-byte DEFER/restart recovery row remains at zero handoff, Receipt, and
release. Use one representative positive row for integrated handoff, Receipt,
terminal fault cuts and digest mismatch, relying on existing focused Host and
Foundation Receipt tests for their complete internal cut matrices. Check the
digest against a machine-known vector.

## Non-scope

No public API, durable schema/field/table, outcome state machine, session
registry, application-specific vocabulary, new Receipt implementation, multi-peer
progression, ESP owner, physical HIL, release claim, or retention/GC policy
extension is added. Source-private read-only Host/terminal views may be added
only if existing durable terminal correlation cannot otherwise be proven.

## Implemented result

- The Runtime derives the ADR-0021 Application-evidence digest with streaming
  SHA-256 over the exact domain, token, transaction, attempt, ordinal, stage,
  length, and evidence bytes. A machine-known vector fixes the exact preimage
  and digest.
- READY reconciliation advances only durable positive evidence whose stage
  meets the original requirement. It commits the existing Host publication
  transition once; exact HANDOFF replay is a no-op and digest/state mismatch
  fences before Receipt or later mutation.
- A definite publication FULL failure reloads the durable active image through
  the existing engine recovery helper before retry. A committed-NEW
  `COMMIT_UNKNOWN` remains fenced until cold recovery classifies HANDOFF.
- The existing downlink and uplink Application reducers use one source-private
  exact handoff gate, then call the existing Receipt sender. Receipt encoding,
  send/retry behavior, and Foundation durable closure remain unchanged.
- Exact Foundation reverse-Receipt closure drives the existing receiver
  terminal FULL. A cold-recovered receiver needs no volatile carrier bind.
  Trusted `now_ms == 0` is legal Foundation time but cannot form canonical
  NM30, so terminalization waits with work remaining and no Storage mutation
  until time becomes non-zero.
- Cold recovery accepts exactly one correlated active receiver row or one
  retained COMPLETE/NONE receiver terminal with the expected transfer, peer,
  session generation, and replay eligibility. Retained NRC1 processing is
  unchanged, preserving duplicate-request responses.
- Every added source-private digest, view, gate, and recovery helper is used by
  this tranche. There is no future-dedicated implementation code.

## Verification evidence

The three verification directories were first confirmed absent, then
configured from the same source snapshot:

```text
cmake -S . -B build-root-mfdt-3d2-normal -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON -DNINLIL_ENABLE_SANITIZERS=OFF -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake -S . -B build-root-mfdt-3d2-asan -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON -DNINLIL_ENABLE_SANITIZERS=ON -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake -S . -B build-root-mfdt-3d2-off -DNINLIL_ENABLE_MFDT_V1_PRIVATE=OFF -DNINLIL_ENABLE_SANITIZERS=OFF -DNINLIL_ENABLE_STRICT_WARNINGS=ON
```

Normal strict-warning build and focused execution:

```text
cmake --build build-root-mfdt-3d2-normal --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test ninlil_mfdt_v1_host_coordinator_acceptance_test ninlil_required_receipt_transition_test -j4
./build-root-mfdt-3d2-normal/ninlil_v1_runtime_capability_test
./build-root-mfdt-3d2-normal/ninlil_mfdt_v1_runtime_owner_test
./build-root-mfdt-3d2-normal/ninlil_mfdt_v1_host_coordinator_acceptance_test
./build-root-mfdt-3d2-normal/ninlil_required_receipt_transition_test
```

Result: configure, build, and all four executables PASS. The Host acceptance
binary reports all 21 named witnesses PASS, including terminal duplicate
replay and cold-recovery witnesses.

ASan/UBSan strict-warning build and focused execution:

```text
cmake --build build-root-mfdt-3d2-asan --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test ninlil_mfdt_v1_host_coordinator_acceptance_test ninlil_required_receipt_transition_test -j4
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_v1_runtime_capability_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_mfdt_v1_runtime_owner_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_mfdt_v1_host_coordinator_acceptance_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_required_receipt_transition_test
```

Result: build and all four executables PASS with no reported ASan/UBSan
finding. LeakSanitizer was not enabled and is not claimed.

MFDT-OFF compatibility build and focused execution:

```text
cmake --build build-root-mfdt-3d2-off --target ninlil_v1_runtime_capability_test ninlil_required_receipt_transition_test -j4
./build-root-mfdt-3d2-off/ninlil_v1_runtime_capability_test
./build-root-mfdt-3d2-off/ninlil_required_receipt_transition_test
```

Result: build and both executables PASS.

The capability table retains the exact 927/4096/32768-byte rows. The 927 and
32768 positive rows prove evidence FULL before HANDOFF, no Receipt before
HANDOFF, exact Receipt, durable reverse closure, cold unbound terminalization,
content release, retained terminal recovery, and no duplicate callback. The
4096 DEFER/restart row proves zero evidence handoff, Receipt, terminalization,
and release. The 32768 row additionally covers publication and terminal
definite failures, committed-NEW `COMMIT_UNKNOWN` plus cold classification,
the zero-time terminal wait, and eight compact identity/digest/length/route/
transfer/ordinal/state/evidence-digest corruption cases.

The complete tracked-plus-untracked scope was added to an isolated temporary
index and checked without changing the real index:

```text
export GIT_INDEX_FILE="$PWD/build-root-mfdt-3d2-normal/3d2-scope-check.index"
git read-tree HEAD
git add -- src/runtime/mfdt_v1/mfdt_v1_engine.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c src/runtime/mfdt_v1/mfdt_v1_runtime_owner.h src/runtime/runtime_v1_bearer_wire.c tests/runtime/v1_runtime_capability_test.c docs/work/2026-08-02-mfdt-application-receipt-terminal-3d2.md
git diff --cached --check -- src/runtime/mfdt_v1/mfdt_v1_engine.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c src/runtime/mfdt_v1/mfdt_v1_runtime_owner.h src/runtime/runtime_v1_bearer_wire.c tests/runtime/v1_runtime_capability_test.c docs/work/2026-08-02-mfdt-application-receipt-terminal-3d2.md
```

Result: PASS with no output.

## Scoped increment accounting

The shared worktree contains tracked and untracked work from earlier
tranches, so repository-wide diff totals would not be attributable. Comparing
the current 3D2 files with the preserved 3D1 isolated index gives:

- five indexed production files: +597/-38 physical lines;
- the engine definite-failure repair: +2/-2 physical lines;
- production net increase: **559 lines**;
- capability test: +481/-2, net **479 lines**; and
- this new work note: net **161 documentation lines**.

No commit or push was performed. No public API, durable state/field/schema,
table, outcome machine, session registry, new Receipt implementation, or new
test framework was added.

## P1 retained-terminal correlation repair

The P1 review found that cold retained-terminal recovery correlated transfer,
source, session generation, terminal state, and replay eligibility but did not
prove that the retained terminal belonged to the exact original OPEN body.
The minimal repair strengthens that existing source-private recovery gate:

- the terminal view now reads the existing NM30 schema-2 transfer revision and
  manifest digest, plus the existing NRC1 OPEN request-body digest;
- every validated NRC1 `OPEN_ACCEPT` slot must carry the same exact OPEN
  request-body digest, while a missing or conflicting digest is corruption;
- recovery reconstructs the canonical revision-2 `TRANSFER_OPEN` body from the
  closed Foundation transaction with the existing sender-expectation and OPEN
  encoder helpers, supplies the durable NM30 manifest digest, and computes the
  existing MFDT request-body digest; and
- recovery accepts the retained terminal only when that digest exactly equals
  the NRC1 digest. A mismatch returns `NINLIL_E_STORAGE_CORRUPT` and establishes
  the existing sticky commit-unknown fence before callback, Receipt, sidecar,
  wire, or Storage mutation.

Exactly one representative negative was added. It retains canonical NM30 and
NRC1 rows, replaces only the closed Foundation content digest with another
canonical SHA-256 digest, and cold-configures the Runtime. The test proves
`NINLIL_E_STORAGE_CORRUPT`, a sticky fence, and zero callback, send, Receipt,
sidecar, PUT, ERASE, or COMMIT change. The following fenced step also performs
zero work. The unchanged durable Foundation then passes the existing exact
retained-terminal recovery case.

The focused verification was repeated after the repair:

```text
cmake --build build-root-mfdt-3d2-normal --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test ninlil_mfdt_v1_host_coordinator_acceptance_test ninlil_required_receipt_transition_test
./build-root-mfdt-3d2-normal/ninlil_v1_runtime_capability_test
./build-root-mfdt-3d2-normal/ninlil_mfdt_v1_runtime_owner_test
./build-root-mfdt-3d2-normal/ninlil_mfdt_v1_host_coordinator_acceptance_test
./build-root-mfdt-3d2-normal/ninlil_required_receipt_transition_test

cmake --build build-root-mfdt-3d2-asan --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test ninlil_mfdt_v1_host_coordinator_acceptance_test ninlil_required_receipt_transition_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_v1_runtime_capability_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_mfdt_v1_runtime_owner_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_mfdt_v1_host_coordinator_acceptance_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d2-asan/ninlil_required_receipt_transition_test

cmake --build build-root-mfdt-3d2-off --target ninlil_v1_runtime_capability_test ninlil_required_receipt_transition_test
./build-root-mfdt-3d2-off/ninlil_v1_runtime_capability_test
./build-root-mfdt-3d2-off/ninlil_required_receipt_transition_test
```

Result: all normal, ASan/UBSan, and MFDT-OFF focused builds and executables
PASS; the sanitizer run reports no finding. The P1 delta against the preserved
pre-P1 isolated index is +120/-1 production lines (net +119), +79/-0 test
lines, and +54/-0 work-note lines. There is no public API, schema, table,
state-machine, or codec addition. No commit or push was performed.
