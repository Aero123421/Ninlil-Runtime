# Public Runtime → MFDT integration audit

Date: 2026-07-31  
Status: **NO-GO for public long-ApplicationData completion**  
Scope: private/default-OFF MFDT candidate wired to the public Runtime

## Outcome

The repository has a working private MFDT engine, Host coordinator, NCL1
carrier, Fabric bearer worker, restart tests, and a direct Fabric E2E.  It does
not yet have evidence that an application can submit logical ApplicationData
larger than the U6 single-frame limit through `ninlil_submit()` and have the
ordinary Runtime drive that same transaction to remote application completion.

This distinction matters: the current
`tests/host/runtime_fabric_actual_e2e_test.c` uses `ninlil_submit()` for the
small Foundation and multi-Service scenarios, but its MFDT scenario constructs
the private session, engines, pipelines, bearer workers, and lab stores
directly.  The three CTest aliases execute the same process; they do not turn
the direct MFDT scenario into a public-submit acceptance test.

## Reproduced source-level blockers

### P0-1 — logical and inline payload length are conflated

`fill_admitted_transaction()` selects `MFDT_V1` above 926 bytes, retains the
logical `payload_length`, and intentionally leaves the 926-byte
`owned_payload` empty.  The current NTS3 codec nevertheless:

- rejects every transaction whose `payload_length` exceeds 926;
- serializes `payload_length` bytes from `owned_payload`; and
- decodes `payload_length` bytes into `owned_payload`.

Consequently the route decision cannot safely reach a durable public
transaction for 927–32768 bytes.  This was not detected by the direct private
MFDT E2E.

Required close:

- NTS3 1.1 must encode logical length separately from inline-owned length;
- single-frame requires `logical == inline <= 926`;
- MFDT requires `logical <= 32768` and `inline == 0`;
- invalid route/length combinations fail closed before any copy;
- normal, sanitizer, cold-restart, oversize, truncation, and repaired-CRC
  semantic mutants must pass.

This repair is assigned to the active public multi-target/NTS3 tranche because
that tranche already owns the codec layout.

### P0-2 — ordinary Runtime step does not own MFDT wire progress

Public admission calls `ninlil_mfdt_v1_spine_arm_sender()`, but no production
Runtime scheduler call site invokes:

- `ninlil_mfdt_v1_spine_sender_pump()`;
- `ninlil_mfdt_v1_spine_take_outbound_ncl1()`; or
- the corresponding session-bound ingress from the ordinary Runtime bearer
  path.

The only non-test ingress bridge is the private
`ninlil_mfdt_v1_session_on_ncg1_data()` function.  The direct Fabric E2E uses a
separate `ninlil_mfdt_v1_bearer_worker_t`, not the Runtime transaction selected
by `ninlil_submit()`.

Required close:

- the Runtime scheduler must route an MFDT transaction to a bounded worker
  owned by the selected Fabric path;
- outbound frames must traverse the configured bearer and inbound frames must
  demux through the bound MFN1 session;
- completion must update the original public transaction and exact target,
  without synthesizing a single-frame Application message;
- loss, duplicate, reconnect, restart, wrong session/generation/cookie, and
  terminal late duplicate paths must be tested.

### P0-3 — the private spine is process-global and single-transfer

`mfdt_v1_spine.c` owns one process-global context and one engine.  That cannot
implement the accepted Host profile of four active transfers, two Runtime
instances in one process, or independent module instances without cross-talk.
The separate four-slot Host coordinator does not currently own the public
Runtime submission path.

Required close:

- move ownership from process-global state to an explicit Runtime/module
  instance;
- use the four-slot Host coordinator and one-slot bounded ESP profile;
- bind each transfer to Runtime, service, exact target, session and Fabric
  path;
- prove two Runtime instances and two MFDT module instances do not share
  storage, scheduler, session, or callbacks.

### P0-4 — production storage is not the Runtime storage authority

The public spine embeds `ninlil_mfdt_v1_lab_store_t`.  It does not use the
Runtime Storage Port or Canonical Domain Store as the production custody
authority.  A public transaction FULL and its NM3S/NM3R/NRC1/NM30 records
therefore do not yet share one accepted crash/recovery authority.

Required close:

- implement a copy-owned MFDT store adapter over the Runtime Storage Port;
- allocate exact namespaces and atomic FULL groups through the accepted Domain
  binding;
- remove the lab store from production-reachable Runtime/module composition;
- execute every-write-point crash/restart and `COMMIT_UNKNOWN` classification
  against Memory, SQLite, and the pinned ESP adapter.

## Required public acceptance

A future completion tranche must add one test whose entry point is only the
installed public Runtime API:

1. register a generic Service with a 32768-byte logical limit;
2. submit 927, 4096, and 32768-byte arbitrary binary ApplicationData;
3. select MFDT without an application-specific API;
4. traverse the real Foundation → Fabric → peer Runtime path;
5. apply the content exactly once at the peer Service;
6. expose target-local progress and terminal evidence through public query;
7. cold-restart sender and receiver at every durable stage;
8. prove a 32769-byte submission rejects without mutation;
9. run two Runtime instances, four concurrent Host transfers, fifth-transfer
   capacity rejection, and deterministic fairness;
10. run the same supported ESP profile on target, while physical transport and
    power-cut remain honestly `NOT_RUN` until hardware evidence exists.

Until those checks exist and pass, MFDT remains a private software candidate;
it must not be represented as public long-payload completion or
`RELEASE_SUPPORTED`.

## Immediate fail-closed repair

`ninlil_mfdt_v1_release_policy_allows_default_on()` previously combined a
hard-coded software-green pin with the honest HIL-red pin.  It returned false
today, but completing only the HIL side later could have enabled the still
incomplete public composition.  The software pin is now also zero and remains
zero until every requirement in this record is backed by acceptance evidence.

Focused verification after the pin repair:

```text
normal:    mfdt_v1_private_build + mfdt_v1_pipeline_private = 2/2 PASS
ASan/UBSan: mfdt_v1_private_build + mfdt_v1_pipeline_private = 2/2 PASS
```

The sanitizer run used fail-fast ASan/UBSan options.  This narrow regression
does not close any of P0-1 through P0-4.

## Instance-owner tranche update

The first non-global ownership seam is now implemented in
`src/runtime/mfdt_v1/mfdt_v1_runtime_owner.{h,c}` and remains private,
default-OFF, and non-installed.

What this tranche closes with executable evidence:

- an opted-in Host Runtime owns an exact four-slot Host coordinator;
- the typed MFDT Store Port currently delegates to the Runtime's existing
  copied `platform->storage` vtable and already-open `runtime->storage`
  handle as a **non-promotable private test seam**;
- the filtering adapter admits only exact `NM3S`, `NM3R`, `NM30`, and `NRC1`
  keys to the MFDT owner while skipping ordinary Runtime rows during MFDT
  recovery;
- two Runtime instances have separate owners, namespaces, slot accounting,
  session configuration, and content custody;
- four concurrent 4096-byte sender transfers are admitted, the fifth is
  rejected with exact MFDT capacity, and a separate Runtime concurrently owns
  one 32768-byte transfer;
- ordinary `ninlil_runtime_step()` reaches the new owner seam.  Until canonical
  bearer carrier/ingress and remote application handoff are connected, active
  owner work returns `NINLIL_E_UNSUPPORTED` with `more_work=1` and sends no
  fabricated empty APPLICATION or Receipt.

Focused evidence:

```text
NORMAL:
  mfdt_v1_runtime_owner_test: PASS
  v1_runtime_capability_test: PASS
  mfdt_v1_host_coordinator_acceptance_test: PASS
  mfdt_v1_media_cu_test: PASS

ASan/UBSan (fail-fast, leak detector disabled on macOS):
  mfdt_v1_runtime_owner_test: PASS
```

This is intentionally **not** a public MFDT completion claim:

- P0-2 remains open: the ordinary Runtime does not yet send/receive NCL1,
  invoke the remote Service callback with reconstructed content, or bind real
  application evidence back to the original exact target.
- P0-3 remains open for the public submission path: the new owner is
  instance-local, but legacy public admission still calls the process-global
  spine until atomic admission/cleanup is migrated.
- P0-4 remains open as an end-to-end crash authority: the new owner uses the
  correct Runtime Storage Port, but main Runtime startup still scans mixed MFDT
  rows with its 4096-byte recovery buffer/allowlist before the owner can
  recover them.
- the ESP exact-one instance owner is explicitly unsupported in this tranche;
  it does not allocate the Host owner and does not silently fall back to the
  global spine.

Required next implementation order:

1. resolve the storage-profile contradiction below before changing startup
   classification; do not weaken the Runtime namespace's closed 4096-byte
   value limit to admit MFDT rows;
2. move MFDT arm/disarm and recovered binding sidecars from the global spine to
   the instance owner, with admission failure and `COMMIT_UNKNOWN` tests;
3. add canonical application-envelope NCL1 carrier demux to the ordinary
   Runtime bearer path and consume the existing step budgets;
4. publish reconstructed content only through the registered Service callback,
   commit remote evidence, then send the real Receipt/TRANSFER_ACCEPT;
5. add public-submit 927/4096/32768, restart/fault, four-slot fairness, and ESP
   exact-one E2E before changing any release/default-ON pin.

## Storage-profile contradiction found during root integration

The initial instance-owner tranche deliberately reused
`runtime->storage`. That is not a promotable production layout.

The accepted Foundation Runtime namespace contract in
`docs/12-foundation-abi.md` and `docs/17-foundation-domain-store.md` limits
every current or future private value in that namespace to 4096 bytes.
`iter_next` returning a required value larger than 4096 is intentionally a
terminal corruption result with no reread or larger temporary allocation.
MFDT's canonical values are larger by design:

- `NM3S` / `NM3R`: up to 34983 bytes;
- `NRC1`: 15020 bytes.

Therefore “teach the ordinary Runtime scanner to skip mixed MFDT rows” cannot
close P0-4. It would either violate the accepted Runtime storage profile or
require the scanner to consume bytes that its closed contract forbids.

The root integration owner selected the first layout for the candidate repair:

1. a distinct, deterministically derived MFDT storage namespace/handle on the
   same copied Storage Port provider, with an explicit cross-namespace
   admission/recovery protocol.

ADR-0021 and `docs/34-v2-runtime-fabric-completion.md` now freeze the candidate
shape:

- 36-byte `NMF1 || SHA-256(domain || u16be(base length) || base bytes)`
  namespace derivation;
- exact `NMS1 || zero[16]` binding key and 53..307-byte binding value carrying
  the full base namespace, domain-separated digest, and CRC32C;
- Foundation scanner remains 4096-byte/closed and never skips MFDT rows;
- sender sidecar pre-arm precedes Foundation admission FULL;
- restart reconciles every exact target in both namespaces before dispatch,
  callback, Receipt, or application effect;
- orphan cleanup and both namespaces' `COMMIT_UNKNOWN` results fail closed;
- teardown order is Bearer, MFDT sidecar, then Foundation storage.

This is a **Normative candidate repair, not public acceptance**. Public submit
E2E, cross-namespace admission/reconciliation, independent implementation
review, and target evidence are still required. Until they pass, public
long-ApplicationData remains NO-GO.

## Exact-one public-admission tranche update (2026-08-01)

The private/default-OFF Host build now routes an exact-one-target public
`ninlil_submit()` admission through the Runtime instance owner rather than the
legacy process-global spine. This closes the admission portion of P0-3 only:

- an unconfigured Runtime retains the ordinary single-frame limit;
- 927 and 4096 byte submissions are durably pre-armed in the derived sidecar
  before the Foundation FULL commit and retain no inline payload copy;
- two Runtime instances have independent owner state;
- 32769 byte and multiple-target long submissions reject without truncating or
  silently falling back to a single frame;
- a definite sidecar pre-arm failure rolls back the staged Foundation write;
- a Foundation commit failure after sidecar pre-arm fences the Runtime and
  reports commit-unknown instead of success or a clean rejection;
- Foundation restart no longer consults the legacy process-global MFDT spine.

Root verification:

```text
normal: v1_runtime_capability + mfdt_v1_private_build
        + mfdt_v1_runtime_owner_private
        + mfdt_v1_runtime_sidecar_fault_private = 4/4 PASS
ASan/UBSan: same focused set = 4/4 PASS
MFDT-OFF: runtime_lifecycle_model + v1_runtime_capability = 2/2 PASS
git diff --check and no-global-public-callsite check = PASS
```

An independent read-only review returned GO with no P0/P1 finding. Its only
P2 was a stale process-global “spine armed” comment; the comment was corrected
to describe the Runtime-owner sidecar without changing behavior.

The overall status remains **NO-GO for public long-ApplicationData
completion**. Cross-store orphan reconciliation, ordinary Runtime
scheduler/carrier/ingress, remote Service apply and Receipt projection, the
bounded ESP owner, and physical HIL remain unimplemented or `NOT_RUN`.

## 2026-08-01 derived-sidecar implementation and fault close

The private Runtime owner no longer reuses the Foundation handle. It now:

- derives the exact 36-byte `NMF1` namespace from the caller's complete base
  namespace bytes;
- opens a separate Storage Port handle and creates/verifies one exact `NMS1`
  binding row before Host coordinator recovery;
- accepts only the binding plus exact 20-byte `NM3S`, `NM3R`, `NM30`, and
  `NRC1` keys, while the Foundation scanner remains unchanged;
- rejects wrong-base collision, partial/third binding bytes, foreign rows, and
  a bootstrap `EXTRA` row without overwriting durable bytes;
- closes and reopens before classifying a binding FULL
  `COMMIT_UNKNOWN`; exact `NEW` succeeds, one/two `ABSENT` outcomes retry
  within the bounded two-attempt rule, and `PARTIAL`/`EXTRA`/`THIRD` fence the
  Runtime;
- tears down in `Bearer -> MFDT sidecar -> Foundation` order with every handle
  exactly once and zero live transactions/iterators.

The authority generators/gates were resynchronized after adding the storage
profile. The independent Python, Node, and C authorities now contain 111
vectors. The C family-count self-test is generated rather than fixed to the
former vector total.

Fresh focused evidence:

```text
normal:
  mfdt_v1_private_build
  mfdt_v1_runtime_owner_private
  mfdt_v1_runtime_sidecar_fault_private
  3/3 PASS

ASan/UBSan:
  mfdt_v1_private_build
  mfdt_v1_runtime_owner_private
  mfdt_v1_runtime_sidecar_fault_private
  3/3 PASS

spec authority (fresh configured suite):
  Python / Node / C checks and self-tests
  10/10 PASS
```

`mfdt_v1_runtime_owner_private` supplies real POSIX SQLite cold
destroy/recreate recovery, two-instance separation, four active Host slots,
fifth-slot rejection, a concurrent 32768-byte transfer, Foundation/binding
isolation, and wrong-base collision non-overwrite. The in-memory fault test
materializes binding `NEW`, `ABSENT`, `PARTIAL`, `EXTRA`, and `THIRD`, asserts
the fence/retry result, leak closure, and teardown order. These are Host
software results, not physical power-cut evidence.

Residual boundary after this close:

- sidecar storage/profile and instance ownership are implemented, but public
  admission still has to pre-arm all exact targets and reconcile the
  Foundation transaction with the sidecar after every cut point;
- ordinary Runtime scheduling/ingress, remote Service apply, target evidence,
  and Receipt remain open;
- the one-slot ESP owner and physical power-cut/RF/Wi-Fi HIL remain `NOT_RUN`;
- ADR-0021 stays `Proposed`, the feature stays private/default-OFF, and no
  release/default-ON claim is permitted.

## Exact-one Host outbound tranche update (2026-08-01)

The private/default-OFF Host candidate now lets the ordinary
`ninlil_runtime_step()` emit the first pending MFDT control frame created by an
exact-one public submission. This is a bounded outbound slice, not transfer
completion:

- a real MFN1 `OFFER` / `ACCEPT` transcript and matching generation, cookie,
  local Runtime, and peer are required before public MFDT admission;
- the Runtime-owned Bearer handle and the existing TxGate are reused; no
  second Bearer handle, gate, public API, or public ABI was added;
- the trusted clock sample already taken at step entry is reused for the
  carrier message and permit;
- Bearer state work runs first, MFDT consumes at most the supplied send budget,
  and ordinary delivery receives the remaining budget;
- the emitted Foundation `APPLICATION` uses the private
  `TRANSFER_RESERVED` service and carries the exact canonical NCL1 `OPEN`;
- a zero send budget leaves the outbox untouched;
- `WOULD_BLOCK` / `UNAVAILABLE` retains the exact pending frame for retry;
- `LOST_UNKNOWN` consumes no retry path, raises the Runtime commit-unknown
  fence, and later steps do not resend the frame;
- wrong peer, generation, or cookie is rejected before MFDT custody or send.

Fresh root verification used new build directories rather than the
implementer's build products:

```text
normal strict:
  v1_runtime_capability
  mfdt_v1_private_build
  mfdt_v1_host_coordinator_acceptance_private
  mfdt_v1_runtime_owner_private
  mfdt_v1_runtime_sidecar_fault_private
  5/5 PASS

ASan/UBSan strict: same focused set = 5/5 PASS
MFDT-OFF strict: runtime_lifecycle_model + v1_runtime_capability = 2/2 PASS
git diff --check, no legacy global-spine public callsite, README vocabulary gate = PASS
```

The remaining MFDT path is still explicit: scheduling and emitting all later
chunks, Runtime ingress/demux and receiver reassembly, remote Service apply,
Receipt/evidence projection, cross-store restart reconciliation, the bounded
ESP owner, and physical HIL are open. The feature therefore remains
`SPEC_ACCEPTED`, private/default-OFF, and is not release-supported.

## Minimal Host OPEN ingress tranche update (2026-08-01)

The ordinary Runtime now has one shared-Bearer receive point for both regular
Application traffic and the private/default-OFF MFDT candidate. This tranche
deliberately closes only the first receiver-side OPEN step:

- the existing `receive_next` call remains the sole ingress owner; no second
  Bearer handle, clock read, TxGate, or transport abstraction was added;
- a message naming the reserved MFDT Service tuple is claimed even when the
  rest of its envelope is malformed, so it cannot fall through to a public
  Application Service;
- the existing Foundation carrier validator checks the exact peer direction,
  session generation/cookie, payload digest, transaction ID, attempt ID, and
  canonical NCL1 bytes before the Runtime copies the frame;
- only an MFN1-admitted canonical `TRANSFER_OPEN` reaches the instance-local
  Host coordinator;
- a successful OPEN is durably held and its exact response remains in the
  existing Host outbox; the reverse binding lets the next ordinary Runtime
  step send that response;
- one received Bearer message consumes one ingress budget entry, and one
  successful durable OPEN projects one Runtime state transition;
- a zero ingress budget does not dequeue the message, and two Runtime
  instances retain independent sender/receiver slots.

Fresh root verification used separate build directories:

```text
normal strict:
  v1_runtime_delivery
  v1_runtime_capability
  mfdt_v1_private_build
  mfdt_v1_host_coordinator_acceptance_private
  mfdt_v1_runtime_owner_private
  mfdt_v1_runtime_sidecar_fault_private
  6/6 PASS

ASan/UBSan strict: same focused set = 6/6 PASS
MFDT-OFF strict: runtime_lifecycle_model + v1_runtime_capability = 2/2 PASS
git diff --check = PASS
```

This is not end-to-end transfer completion. Sender-side OPEN_ACCEPT handling,
later manifest/page/chunk/finalize scheduling, receiver reassembly,
Application Service publication and Receipt projection, stateless
control-route response draining, cross-store reconciliation, the bounded ESP
owner, and physical HIL remain open.

## Host Runtime transfer/reassembly milestone (2026-08-01)

The private/default-OFF Host path now completes the MFDT transport portion
between two Runtime instances through ordinary `ninlil_runtime_step()` calls:

- every accepted MFDT request and response is routed by transfer, session,
  peer, direction, and Application binding;
- canonical OPEN, manifest/page, chunk, finalize, and transfer-accept traffic
  reaches receiver reassembly, content-digest verification, and `READY`;
- a five-route round-robin drain covers four Host slots plus the control route;
  a persistently `WOULD_BLOCK` route retains its exact frame while another
  eligible route proceeds;
- `LOST_UNKNOWN` consumes the selected Host frame and raises the existing
  fail-closed Runtime fence without retry;
- a trusted local clock-epoch change uses the existing durable engine fence
  for every active transfer, invalidates READY data not yet handed off, and
  permits later transfers only under the new epoch;
- complete Foundation carrier validation runs before sender durable admission,
  so invalid identity, target, header, flag, or Application-instance fields do
  not create candidate transfer rows.

Fresh root verification used new build directories and found one stale
fairness assumption in the existing Runtime capability test. That test was
updated to require cross-route progress followed by byte-stable retry; no
production code was changed for the test repair.

```text
normal strict focused suite: 7/7 PASS
ASan/UBSan strict focused suite: 7/7 PASS
normal strict MFDT suite: 29/29 PASS after building its explicit sidecar fixture
MFDT-OFF strict: runtime_lifecycle_model + v1_runtime_capability = 2/2 PASS
MFDT-OFF installed archive symbol check = PASS
tracked/untracked whitespace gates and README vocabulary gate = PASS
```

This milestone ends at verified receiver `READY`; it does not claim remote
Application Service application or delivery completion. Application prepare /
handoff, Receipt and evidence projection, restart restoration of carrier
bindings, cross-store reconciliation, the ESP owner, and physical HIL remain
open.
