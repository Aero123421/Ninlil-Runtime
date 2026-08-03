# MFDT READY to Foundation Application handoff 3D1

Date: 2026-08-02  
Status: **Host software verified / 3D1 complete**

## Implementation contract

- Treat the canonical Application binding embedded in the durable receiver
  OPEN as the only Application authority. The live MFDT carrier binding remains
  transport-only and is never used to reconstruct the Application after a
  restart.
- Once NM3R contains verified whole content, its whole digest, publication
  `READY`, and a non-zero publication token, reconstruct that Application and
  commit exactly one inbound Foundation transaction FULL. The transaction has
  the OPEN logical payload length, zero inline bytes, the MFDT route, the exact
  transfer ID, and target ordinal. No Application callback may run before this
  FULL succeeds.
- Repeated steps and cold restart reconcile the READY row against the existing
  Foundation transaction. An exact match is a no-op. Any identity, digest,
  logical length, transfer ID, target ordinal, route, or incompatible state
  mismatch fails closed as storage corruption before callback or wire output.
- Reuse the existing Foundation callback-token, deferred-delivery, restart,
  result, and evidence machinery. The public delivery token `context_id`
  remains the Foundation transaction ID. During callback only, the existing
  ingress reducer borrows the verified complete sidecar payload read-only; the
  private publication token is never exposed through public API.
- A Foundation transaction/evidence FULL may progress through the existing
  callback path. MFDT-backed ingress stops there: it emits no Application
  Receipt and performs no MFDT handoff, terminalization, or content release.
- A Foundation or MFDT `COMMIT_UNKNOWN` fences all later callback, wire, and
  mutation until cold recovery. Definite failure retains the existing
  Foundation error contract. ESP remains unsupported.

## Representation decision

No public API, durable schema, table, state field, outcome state machine, or
session registry is added. A source-private read-only Host view exposes one
already-canonical receiver OPEN together with its verified whole publication.
The Runtime bridge decodes that OPEN into the existing
`ninlil_bearer_message_t`, and the existing NTS3 transaction fields carry all
durable correlation needed by 3D1.

## Implemented result

- Runtime maintenance observes trusted time before READY reconciliation. A
  same-step clock-epoch change therefore invalidates stale READY before any
  Foundation transaction or callback can appear.
- Receiver cold recovery keeps the Application authority in canonical NM3R
  OPEN. The first later authenticated carrier may restore only the volatile
  transport route; definite Host failure retries that same route, while
  `COMMIT_UNKNOWN` fences before later wire, callback, or mutation.
- READY reconciliation creates or exact-matches one existing inbound NTS3
  Foundation transaction. The durable transaction has logical payload length,
  zero inline payload, MFDT route, transfer ID, and ordinal. Existing callback,
  defer, completion, evidence, and reconcile code owns all later Application
  progress.
- The callback reducer borrows only the verified whole receiver payload. The
  public callback token uses the Foundation transaction ID; the private
  publication token remains internal.
- Positive Application evidence becomes Foundation FULL, but 3D1 suppresses
  Receipt and leaves outcome, terminalization, handoff, and content release
  open for 3D2.

## Verification target

- pre-READY produces no Foundation transaction or callback;
- READY commits Foundation before callback and delivers byte-exact 927, 4096,
  and 32768-byte payloads without partial exposure;
- repeated step, repeated READY, and cold restart do not recommit or redeliver
  completed evidence;
- a DEFER keeps the same Foundation transaction/context correlation, but a
  cold restart converts the durable ACTIVE token to `TOKEN_EXPIRED` with
  delivery `RECOVERY_REQUIRED`; the old token completion is rejected,
  post-restart callback and Receipt remain zero, and the MFDT sidecar remains
  retained. Active-token continuation across restart is not claimed;
- restart from READY/Foundation-absent and READY/Foundation-present without
  evidence resumes at the exact required boundary;
- representative Application identity, digest, transfer ID, ordinal, route,
  and state mismatches fail closed with zero callback and wire;
- Foundation definite and `COMMIT_UNKNOWN` cuts obey the existing contract;
- after Foundation evidence FULL, MFDT handoff, Receipt, terminalization, and
  content release remain zero;
- normal, ASan/UBSan, MFDT-OFF, strict-warning, and diff checks remain green.

## Explicit 3D2 remainder

This tranche does not derive the canonical Application evidence digest, commit
`G_R_HANDOFF`, reconstruct or send an Application Receipt, close Receipt
custody, terminalize an MFDT receiver, release retained content, implement the
ESP owner, or claim physical HIL/release support.

## Verification evidence

For this P2 rerun, the three build directories were first confirmed absent:

```text
for d in build-root-mfdt-3d1-p2-normal build-root-mfdt-3d1-p2-asan build-root-mfdt-3d1-p2-off; do if test -e "$d"; then echo "$d exists"; else echo "$d absent"; fi; done
```

Result: all three printed `absent`. They were then configured from the same
source snapshot. Normal host configure, build, and both focused tests:

```text
cmake -S . -B build-root-mfdt-3d1-p2-normal -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON -DNINLIL_ENABLE_SANITIZERS=OFF -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake --build build-root-mfdt-3d1-p2-normal --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test -j4
./build-root-mfdt-3d1-p2-normal/ninlil_v1_runtime_capability_test
./build-root-mfdt-3d1-p2-normal/ninlil_mfdt_v1_runtime_owner_test
```

Result: configure PASS, build PASS with strict warnings enabled, and both tests
PASS. The capability table covers 927, 4096, and 32768 bytes. Its 4096-byte
case cold-recreates while DEFER is outstanding, then verifies the same
Foundation transaction/context, `TOKEN_EXPIRED`, delivery
`RECOVERY_REQUIRED`, rejected old-token completion, zero post-restart
callback/Receipt/wire, raw NM3R/NRC1 retention before recreate, and an exact
4096-byte sidecar borrow after recreate. The 32768-byte evidence-present case
reuses that one fixture to cold-recreate seven compact mutations: immutable
source identity, digest, logical length, route, transfer ID, ordinal, and
delivery state. Every row returns `NINLIL_E_STORAGE_CORRUPT`, publishes the
fence, and leaves callback, Receipt flags, and wire output at zero; a later
step remains fenced without callback or bearer send.

ASan/UBSan host build and focused tests:

```text
cmake -S . -B build-root-mfdt-3d1-p2-asan -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON -DNINLIL_ENABLE_SANITIZERS=ON -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake --build build-root-mfdt-3d1-p2-asan --target ninlil_v1_runtime_capability_test ninlil_mfdt_v1_runtime_owner_test -j4
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d1-p2-asan/ninlil_v1_runtime_capability_test
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build-root-mfdt-3d1-p2-asan/ninlil_mfdt_v1_runtime_owner_test
```

Result: configure PASS, build PASS, and both tests PASS with no reported
ASan/UBSan finding. These commands do not enable LeakSanitizer, so this note
does not claim leak-detection coverage.

MFDT-OFF compatibility build and capability test:

```text
cmake -S . -B build-root-mfdt-3d1-p2-off -DNINLIL_ENABLE_MFDT_V1_PRIVATE=OFF -DNINLIL_ENABLE_SANITIZERS=OFF -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake --build build-root-mfdt-3d1-p2-off --target ninlil_v1_runtime_capability_test -j4
./build-root-mfdt-3d1-p2-off/ninlil_v1_runtime_capability_test
```

Result: configure PASS, build PASS, and test PASS.

The repository has both tracked and untracked 3D1 files. To check the complete
explicit 3D1 scope without changing the real index, the current files were
added to an isolated index inside the fresh ignored normal build directory,
then checked as one cached diff:

```text
test ! -e build-root-mfdt-3d1-p2-normal/3d1-scope-check.index
export GIT_INDEX_FILE="$PWD/build-root-mfdt-3d1-p2-normal/3d1-scope-check.index"
git read-tree HEAD
git add -- src/runtime/runtime_public.c src/runtime/runtime_v1_bearer_wire.c src/runtime/runtime_v1_bearer_wire.h src/runtime/runtime_v1_delivery_durable.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c src/runtime/mfdt_v1/mfdt_v1_runtime_owner.h tests/runtime/v1_runtime_capability_test.c tests/runtime/mfdt_v1/mfdt_v1_runtime_owner_test.c docs/work/2026-08-02-mfdt-ready-foundation-handoff-3d1.md
git diff --cached --check -- src/runtime/runtime_public.c src/runtime/runtime_v1_bearer_wire.c src/runtime/runtime_v1_bearer_wire.h src/runtime/runtime_v1_delivery_durable.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c src/runtime/mfdt_v1/mfdt_v1_host_coordinator.h src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c src/runtime/mfdt_v1/mfdt_v1_runtime_owner.h tests/runtime/v1_runtime_capability_test.c tests/runtime/mfdt_v1/mfdt_v1_runtime_owner_test.c docs/work/2026-08-02-mfdt-ready-foundation-handoff-3d1.md
```

Result: PASS with no output. The fresh strict-warning builds above supply the C
syntax/compiler check; this temporary-index command supplies the scoped
tracked-plus-untracked whitespace/error check.

## Scoped increment accounting

The repository was already a heavily shared dirty worktree, and the MFDT
source directories and this note are untracked relative to `HEAD`; therefore a
repository-wide `git diff --numstat` cannot honestly attribute this tranche.
The agent-local implementation ledger is:

- 815 physical lines in the new named production function groups: Host READY
  view (122), canonical OPEN target/parse (218), Runtime READY reconcile plus
  payload borrow (181), and Foundation MFDT ingress exact-match/commit (294);
- approximately 350 narrow integration lines in existing recovery/rebind,
  Runtime-step ordering/accounting, reducer/Receipt guards, and private
  declarations;
- 859 current physical lines for the handoff-specific callback and table block,
  replacing the prior 153-line cold-restart test (approximately +706); and
- 106 physical lines for the focused same-step epoch invalidation test block.

That is approximately 1,980 attributable production-and-test lines, excluding
this work note. The P2 mismatch-table repair itself is a net 76 test lines and
zero production lines. No commit or push was performed. No public API, schema,
durable state, table, outcome machine, session registry, or new test framework
was added.
