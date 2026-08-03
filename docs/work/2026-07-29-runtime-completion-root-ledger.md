# Runtime completion root ledger — 2026-07-29

Status: **ACTIVE / NOT RELEASE-SUPPORTED**

This record is the root integration ledger for the current completion tranche.
It separates specification, software execution, target build, and physical HIL.
A green subset, a compile-only target, or a test count is never used as evidence
for a broader completion claim.

## Claim boundary

- Host support target: Linux and macOS.
- Target: ESP32-S3 with the pinned ESP-IDF toolchain.
- This completion tranche is implemented, reviewed, and verified with Codex
  agents only. Grok Build is prohibited for implementation, consultation,
  review, QA, and fallback. Historical work records that mention Grok remain
  provenance only and do not authorize current use.
- Physical USB, Wi-Fi AP, SX1262 RF, flash power-cut, multi-node failover, and
  soak evidence remain `NOT_RUN` until a connected device produces sealed
  artifacts.
- No physical result may be inferred from Host simulation, Docker target
  compilation, map files, or static stack analysis.
- The ESP32-S3 platform row in `compatibility-matrix.json` is held at
  `SPEC_ACCEPTED`. Its former `TARGET_CANDIDATE` value was an overclaim because
  the completion contract requires target-executed tests in addition to
  compile/link evidence. `state_ceiling=TARGET_CANDIDATE` remains the permitted
  next ceiling; it is not the current state.
- Final source-package evidence must be generated from one clean immutable Git
  commit, not from this moving worktree.

## Objective-to-evidence ledger

| Objective | Required closing evidence | Live state |
| --- | --- | --- |
| Portable Core / Host Runtime | Normal and ASan/UBSan suites, installed consumers with SQLite ON/OFF, clean-room package, public ABI/symbol review | **REVERIFY AFTER INTEGRATION** |
| API and contracts | Public header/ABI checks; one Runtime with multiple DesiredState/EventFact services; simultaneous command receive, event/measurement-shaped uplink, and query/list polling; arbitrary bounded ApplicationData payloads. Native subscription and reserved M2 families remain explicit roadmap non-goals under ADR-0024 | **HOST NORMAL + SANITIZER + ESP TARGET BUILD PASS; PHYSICAL HIL NOT_RUN** |
| Storage / retry / dedupe | POSIX SQLite conformance, restart and commit-unknown matrices, duplicate suppression, crash/fault tests | **REVERIFY AFTER INTEGRATION** |
| Complete fragmentation / reassembly | Frozen authority bridge, every declared fault hook, P10 production composition, normal + sanitizer tests, ESP build/map | **LANE SOURCE-FROZEN; ROOT AGGREGATE REVERIFY PENDING** |
| Wi-Fi real path | Real Host TCP/TLS/Fabric 10,000-transfer path, durable permit and restart rejection, bounded ESP allocator, target build/map | **R7 CO-TENANT ACCEPTED; WI-FI REMAINS PROPOSED; PHYSICAL EVIDENCE RED** |
| Relay / multi-parent | Bounded atomic bundle, durable used-attempt ledger, exact handoff CAS, global writer fence, normal + sanitizer + restart/fault + ESP gates | **JOINT SPEC_ACCEPTED; INDEPENDENT-REVIEWED SOFTWARE CANDIDATE; PHYSICAL HIL RED** |
| Multi-frame durable transfer | Independent authority, chunk/reassembly/custody/restart/fault matrices, Fabric integration, normal + sanitizer + ESP gates | **INDEPENDENT-REVIEWED SOFTWARE CANDIDATE; MF-O08 / PHYSICAL EVIDENCE RED** |
| OSS release surface | Apache-2.0, notices, dependency inventory, SBOM, deterministic archives, Linux/macOS CI, docs/link/version/workflow gates | **WORKTREE GATES PARTIAL; COMMIT-TREE GATE PENDING** |
| Security | Repository policy, dependency/release integrity, transport/storage/runtime scan, validated finding closure | **PENDING FINAL STABLE DIFF** |

The exact one-node/multi-service Host and target acceptance is recorded in
[2026-07-29-multi-service-node-host-acceptance.md](2026-07-29-multi-service-node-host-acceptance.md).
It does not mislabel reserved M2 families or native subscription as M1a
features.

## Root observations

### 2026-07-29 public Host SDK tests-OFF install

Fresh Release producers with `NINLIL_BUILD_TESTS=OFF` passed for both optional
storage configurations:

- SQLite OFF: **PASS**
- SQLite ON: **PASS**

Each gate proved that zero tests are registered, built and installed the public
Runtime, rejected private/test-object and absolute-path leakage, verified the
required exported Runtime/OpenSSL symbols, verified the exact optional SQLite
surface, and configured/built/ran an independent public-header-only consumer
through `create -> step -> destroy`. These are current-worktree Host package
results; Linux CI and immutable commit/archive clean-room evidence are still
required.

The public ABI manifest was regenerated twice and compared with its committed
golden and declaration coverage authority: `abi_manifest_repeatable`,
`abi_manifest_golden`, and `abi_manifest_coverage` are **3/3 PASS**.

### 2026-07-29 worktree release gate

- Workflow YAML parses successfully.
- `git diff --check` succeeds.
- Every non-vendored Python tool and every JavaScript/Node tool parses
  successfully.
- Markdown links, compatibility matrix, third-party notices, release workflow
  identity, and forbidden-vocabulary gates pass.
- The self-tests for Markdown links, compatibility, notices, release identity,
  forbidden vocabulary, deterministic archive payload, version identity, SPDX
  SBOM, and the aggregate distribution-authority gate all pass; their seeded
  negative mutations are rejected.
- Two-read worktree release archives contain the same member inventory in tar
  and zip, with canonical metadata, all required pinned files, and no denylist
  entry. The exact count is intentionally recorded only with the final
  immutable source snapshot because this worktree is still moving.
- The pinned `rhysd/actionlint:1.7.12` container accepts every current workflow.
- The pinned `koalaman/shellcheck:stable` container initially found six
  actionable diagnostics. The scripts now use quoted OpenSSL flag arrays,
  explicit fail-closed conditionals, an explicit ILP32 probe branch, and one
  shell-owned OpenSSL peeled-commit pin. A complete second scan of every
  repository `*.sh` file is **PASS**, as is `bash -n` for the same inventory.
  The MFDT ESP proof dry-run and the Wi-Fi certificate-fixture generator also
  pass after those repairs.
- Worktree forbidden-vocabulary and deterministic archive checks succeed.
- Immutable `git:HEAD` archive check currently fails because legal-file pins and
  release tooling are newer in the worktree than the last commit. This is an
  expected hard failure until one coherent commit is created; it must pass
  after the final commit and before push handoff.

### 2026-07-29 default integration build

The first root build used:

```sh
cmake -S . -B build/root-integration-normal -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
cmake --build build/root-integration-normal --parallel 4
```

It stopped while a concurrent fragmentation-authority edit was incomplete:

```text
domain_scan_crossrow_d3s3_projection.py: D3-S4 source authority check failed
domain_scan_crossrow_d3s4_vector_gen.py: d3s4 suffix not generated
```

This is a live red gate, not a waived failure. The same clean build must be
rerun after source editing is frozen.

### 2026-07-29 MFDT isolated rerun

The root integration owner configured fresh normal and ASan/UBSan build
directories with `NINLIL_ENABLE_MFDT_V1_PRIVATE=ON`, built the independent C
oracle, and ran the exact
`^(mfdt_v1_|multi_frame_durable_transfer_)` inventory.

- Normal: **26/26 PASS**
- ASan/UBSan: **26/26 PASS**
- The inventory includes Python, Node, and C authorities, mutation self-tests,
  lifecycle 10,000, transactional faults, restart/CU, ESP-store Host
  conformance, footprint, target dry-run, install boundary, and the honest
  `NOT_RUN` HIL runner.
- Actual MFDT-over-repaired-Fabric and final ESP map evidence must still be
  rerun after the shared Wi-Fi/Fabric source is frozen.

#### Post-rerun COMMIT_UNKNOWN retry finding

A new fail-closed regression test reproduced a software defect that the
26-test inventory did not cover. When an ESP-style FULL returns
`CU_NEW_NOT_PROMOTED`, the first receiver call correctly returns
`NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN`, but the same request ID can then hit the
durable NRC1 response and return `NINLIL_MFDT_V1_OK` while the physical FULL
promotion gate is still off. That is an external-success bypass of the current
ADR-0021 unattested-ESP rule.

The reproducer is
`test_cu_new_nrc1_retry_stays_unpromoted` in
`tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c`. It is intentionally red until the
runtime/store trust boundary and restart behavior are repaired. MFDT therefore
remains **NO-GO** even though the earlier isolated inventory was green. The
repair must cover same-process retry, cold restart, exact OLD/NEW/third
classification, normal and sanitizer runs, and must not fabricate physical
HIL attestation.

#### COMMIT_UNKNOWN retry repair close

The private candidate now applies the same replay-eligibility boundary to
internal and public NRC1 lookup. On an unattested target, an exact cached
response cannot turn the prior `CU_NEW_NOT_PROMOTED` into external success.
Warm retry and cold recovery with active+NRC1, NRC1-only, or NM30+NRC1 all
remain `ERR_COMMIT_UNKNOWN` with an empty response. Host FULL-capable storage
keeps bit-exact replay. `ESP_PLATFORM` fixes the target authority at compile
time, so a caller-supplied Host profile cannot bypass it.

Root independently rebuilt and reran the full focused inventory after source
freeze:

- fresh normal: **26/26 PASS**;
- fresh ASan/UBSan: **26/26 PASS**;
- the 10 specification/oracle/acceptance tests are included in both runs;
- exact OLD/NEW/PARTIAL/EXTRA/THIRD, warm/cold retained-state shapes,
  install-symbol boundary, footprint, target dry-run, and honest
  `NOT_RUN` HIL result are included.

The target map proof reported ESP-IDF v5.5.3 final ELF/link, MFDT BSS
`963 / 49152`, and no lab-store leakage. Physical power-cut execution remains
`NOT_RUN`.

This repair does not close production promotion. ADR-0021 now tracks
`MF-O08 OPEN`: the platform-rooted evidence schema, trust anchor,
device/build/profile binding, monotonic anti-rollback state, and
expiry/revocation authority do not exist yet. The reserved attestation
function therefore remains deliberately fail-closed. MFDT is no longer
software-NO-GO for the NRC1 bypass, but it remains `Proposed` and this ledger
does not claim that only physical HIL is left.

#### 2026-07-30 full-spec review reopened MFDT software NO-GO

The later full normative/implementation review found failures outside the
26-test repair inventory, so the earlier narrow repair close must not be read
as whole-feature acceptance. Reproduced blockers include:

- the Host contract declares four concurrently active transfers, while the
  current receiver owns one workspace and can answer a second `OPEN` with an
  `OPEN_ACCEPT` bound to the first transfer;
- the normative `NM30` terminal invariant and mandatory expiry profile cannot
  construct the same canonical `ABORTED` record;
- malformed one-byte `ABORT`, expired and overflowing `OPEN`, and
  semantically invalid durable restart records are accepted on current paths;
- the current terminal serializer does not preserve the declared canonical
  `NM30` layout.

MFDT is therefore **software NO-GO** again. The repair may not reduce the Host
contract from four active transfers to one. It must first freeze an internally
consistent four-slot/fair-scheduling and terminal-record contract, add exact
RED vectors, then repair canonical validation/codecs and the four-slot engine.
Fresh normal, ASan/UBSan, crash/restart, ESP target build, and independent
full-spec review are mandatory before any `SPEC_ACCEPTED` promotion. `MF-O08`
and physical power-cut/RF/Wi-Fi evidence remain separate open gates.

### 2026-07-29 RRMP repaired-source root rerun

After the bounded RRM1 piece store, QST4 attempt/authority tuple persistence,
handoff v2, restart, strict import, and ESP target-smoke repairs were
source-frozen, root independently ran:

```sh
NINLIL_CI_COMPLETION_JOBS=4 \
  bash tools/ci_completion_feature_host_matrix.sh rrmp all_profiles
```

Observed:

- feature OFF residual inventory: **15/15 PASS**;
- feature ON normal inventory: **16/16 PASS**;
- feature ON ASan/UBSan: **7/7 PASS**;
- frame/stack and Storage ABI gates: **PASS**;
- tests-OFF, feature OFF and feature ON build/install boundaries: **PASS**;
- physical two/three-hop RF, failover, split-brain, and power-cut HIL:
  **NOT_RUN**.

The implementing lane also produced a pinned ESP-IDF v5.5.3 ESP32-S3 final ELF
and map/resource PASS. A separate Sol xhigh source review is still in progress,
so this evidence does not yet promote the current NO-GO software verdict.

That review subsequently found a further P1 in two write paths:
`parent_select` and `forward_admit` manually removed an inserted attempt after
`finish_writepoint_full` had already reconstructed RAM from exact durable OLD.
For an insertion in the middle of the sorted attempt table, the stale index
could remove an unrelated OLD row; `parent_select` also captured the former
selected parent after overwriting it.

The repair now suppresses pre-recovery rollback only when the writepoint proves
an exact durable-OLD reconstruction, captures the selected parent before
mutation, and adds middle-index regressions for both paths. The reviewer
confirmed each regression RED before the repair. Root then reran the complete
Host matrix independently:

- feature OFF residual inventory: **15/15 PASS**;
- feature ON normal inventory: **16/16 PASS**;
- feature ON ASan/UBSan: **7/7 PASS**;
- frame/stack and Storage ABI gates: **PASS**;
- tests-OFF, feature OFF and feature ON install boundaries: **PASS**.

The implementation reviewer found no remaining P0/P1 in scope and refreshed
the software record to workspace `388048`, export scratch `307200`, piece
scratch `61440`, target store `307456`, aggregate `1064144`, ESP BSS `3140`,
and QST4 vocabulary. Formal state remains NO-GO until a different reviewer
checks the repaired delta. Physical HIL remains `NOT_RUN`.

That different independent review subsequently completed with P0/P1 both zero.
ADR-0019 and ADR-0020 were then promoted together to `SPEC_ACCEPTED`; all
machine authorities now claim `spec_accepted=1` and keep implementation, HIL,
release, and public ABI at zero. Post-promotion generator/Python/Node/C gates,
12,882 donor mutations per semantic gate, normal and ASan/UBSan 18/18
inventories, and the 10,000-cycle lifecycle test passed. The root integration
also synchronized the compatibility matrix and README. Physical two/three-hop
RF, failover, split-brain, flash power-cut, and soak evidence remains
`NOT_RUN`.

### 2026-07-29 R7 fragmentation / D3-S4 authority close

The focused lane is source-frozen with all declared semantic hooks connected
to real calls:

- typed authority bridge: **468/468 PASS** (`283` prefix, `185` suffix);
- production cases `154`, formal D1 `29`, formal Mode33 `2`, cross-mode `1`,
  composition `1`, storage-fault production `1`, P11 `16`, semantic hooks
  `34`, pending hooks `0`;
- fresh focused normal inventory: **8/8 PASS**;
- fresh D3-S4 + DSD1 ASan/UBSan inventory: **2/2 PASS**;
- ESP-IDF v5.5.3 ESP32-S3 component archive and final ELF link: **PASS**,
  with the D3-S4 object present exactly once;
- generator check, independent projection, fixture re-emission, packaging
  gate, and scoped whitespace check: **PASS**.

The later default aggregate rerun built this source and passed every registered
fragmentation/D3-S4 test. The all-private aggregate and immutable commit-tree
reruns are still required, so the broader row cannot advance beyond target
software candidate.

### 2026-07-29 multi-service Host acceptance

The real Portable Runtime → Fabric → peer Runtime path now runs one Endpoint
with four complementary public services at once:

- `display.command` DesiredState receive,
- `access.event` EventFact send,
- `temperature.telemetry` periodic and query-response EventFact send,
- `temperature.query` DesiredState receive.

All four initial transactions overlap in one bounded progress loop. The
temperature response is admitted only after the query callback returns. One
accepted packet is silently lost and one packet is duplicated; callback
routing, payload identity, exactly-once application effects, terminal evidence,
`transaction_query`, and `transaction_list` are all asserted. UTF-8, preset,
fixed-width sensor, and opaque binary payload forms are covered.

Fresh Fabric-only normal build and execution:

```text
./build/root-multiservice-live/ninlil_runtime_fabric_actual_e2e_test
runtime_fabric_actual_e2e_test: PASS
```

This acceptance exposed two real integration defects rather than being shaped
around the old implementation:

1. EventFact correctly carries an all-zero wire deadline epoch, but Fabric had
   incorrectly fed that zero value into the non-zero retry-lifetime epoch
   selector. The Fabric projection now uses the attempt-admission trusted
   epoch only for valid EventFact `NO_DEADLINE`, as ADR-0017 requires.
2. Two simulated peers used the same deterministic entropy stream and could
   generate colliding transaction IDs. The two-peer test now assigns distinct
   deterministic streams, matching the independence expected of real nodes.

The explicit CTest name is `multi_service_node_host_actual_e2e`. After the P1
review repairs were source-frozen, root independently configured fresh build
directories and ran the exact Fabric lifecycle, Host acceptance, actual E2E,
and multi-service alias inventory:

- normal: **4/4 PASS**;
- ASan/UBSan: **4/4 PASS** with fail-fast instrumentation
  (`detect_leaks=0` on macOS);
- complete direct Fabric matrix: **9/9 normal and 9/9 sanitizer PASS**;
- ESP-IDF v5.5.3 ESP32-S3 final ELF: **PASS**, with the shared
  `examples/multi_service_node/` module linked and called.

The Host and ESP smoke use the same role-neutral four-Service profile and
response state machine. Physical execution remains `NOT_RUN`; the target build
is not HIL evidence.

### 2026-07-29 default aggregate rerun after lane freezes

A fresh default Host build completed **706/706 build steps** and ran **385
CTest registrations**. **383/385 passed**. The only failures were
`release_distribution_authority_gate` and `release_archive_cleanroom_gate`,
both at the deliberately fail-closed immutable `git:HEAD` archive check:
the current worktree legal-file pins and release tooling are newer than
`e756aa0`. All runtime, storage, retry, dedupe, Fabric, RRMP, fragmentation,
MFDT, ABI, documentation, Host packaging, and target-logic tests in that
configuration passed.

This is not a waiver. The two release gates must turn green after the coherent
checkpoint commit and before push; until then the immutable release row remains
open.

### 2026-07-29 Wi-Fi ESP TLS resource freeze

The Wi-Fi/TLS lane is source-frozen at the deliberately narrow
`wifi_tls_only_target_software_candidate` claim:

- The exact OpenSSL `3.5.7` release archive passed its pinned SHA-256 check and
  produced a static-only macOS arm64 authority install (`libssl.a` and
  `libcrypto.a`) with the expected release tag, peeled commit, configure
  options, and manifest. A second invocation accepted the cached install, and
  the provenance gate's seeded-negative self-test is **PASS**. The
  pinned-authority Wi-Fi/Fabric E2E completed 10,000 ordered transfers with
  exact live/restart replay denial; every registered negative/recovery
  scenario also passed.
- Host normal inventory: **33/33 PASS**
- Host ASan/UBSan inventory: **33/33 PASS**
- ESP-IDF v5.5.3 clean build/map/resource gate: **PASS**
- Exact live-allocation metadata, requested-size/canary validation,
  owner-scoped free, and ordinary OOM versus corruption classification are
  implemented and fault-tested.
- With the accepted R7 co-tenant reservation, the conservative internal-only
  requirement is 327,984 bytes and the tiered candidate envelope is 164,144
  bytes. The tiered value is not allowed to silently replace the conservative
  requirement before physical evidence exists.

The machine vector digest is
`38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff`.
Reproduction commands, toolchain identity, map totals, and stack/resource
figures are recorded in
[2026-07-29-wifi-esp-psram-tier-resource-close.md](2026-07-29-wifi-esp-psram-tier-resource-close.md).

The R7 `OTHER_REGISTERED` allocator co-tenant lane is implemented and accepted
by ADR-0026 after independent P0/P1/P2=0 review. A root-owned clean
ESP-IDF v5.5.3 rerun also passed final ELF/link/map/resource/closure with
304-byte R7 reservation, 171703/341760-byte DIRAM use, 5913-byte link slack,
and closure root
`755959d4d2d7f00501b1967e1aa7002fb39a5460cbb54e137fd47323176c0387`.
The rerun artifacts were
`629ca56667e8c9de2e9f0474b91f423397720cf8a8c8d754176fa57fed32c8a6`
(ELF) and
`81f5ea019aaf76f81ffa76c52059eddca9f01dcb6ab9a713c92e14545f4bddb0`
(map).

This is not a Wi-Fi release close. Wi-Fi driver/lwIP/socket/netif/DHCP/PBUF
resource peaks are not
measured, and real TLS handshakes, PSRAM exhaustion/fragmentation, AP
disconnect/reconnect, and soak remain physical `NOT_RUN`. C7/C8 and
`RELEASE_SUPPORTED` therefore remain red.

### 2026-07-29 complete traceability Coverage V2

The former sampled traceability row has been replaced by a fail-closed,
profile-aware Coverage V2 authority. It binds all `254` normative headings,
all `40` foundation requirement IDs, `303` delegated vectors, and `14`
invariants (`21` independently checked subclaims) to configured, enabled
CTest registrations and their source anchors. Disabled tests, tests hidden by
`if(FALSE)`, fenced pseudo-headings, omissions, duplicates, reordering,
source-byte drift, and invariant text moved outside its normative section are
explicit negative mutations.

Root independently reproduced the result from fresh configure trees:

- baseline profile: legacy plus V2 traceability **4/4 PASS**;
- all-private profile: legacy plus V2 traceability **4/4 PASS**;
- partial profile (Domain plus all private features except MFDT): the complete
  profile check is correctly absent rather than falsely labelled baseline or
  all-private;
- deterministic materialization digest:
  `c1e61b6a0146b8576d54a1e523036895f50c5b693e6ed62cf0b78259907e0d7a`.

`NIN-PR1-TRACE-COVERAGE-001` is therefore `verified` for the declared Host
profiles. This does not create physical HIL, RF, legal-compliance, or remote-CI
evidence.

### 2026-07-30 integrated Host E2E fixture repair

The direct all-private Host integration runner initially failed before it
could exercise the intended topology. The fixture had drifted across two
production contracts:

- current RRMP requires an Authority v2 assignment commit and activation;
  registering the parent set alone is not send authority;
- the cold-restart fixture stored an over-84-KiB logical export as one value,
  while the platform contract limits a value to 64 KiB and persists RRMP as
  manifest plus chunk rows.

The fixture now provisions the actual Authority v2 transition and exports and
imports the exact committed `RRM1` plus `C0..C4` physical rows. It does not
weaken the route fence or enlarge the storage-value limit. Root independently
ran:

```sh
bash tools/host_completion_integrated_e2e.sh
```

Both strict and ASan/UBSan scenarios passed with the same digest
`6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e`.
Both P1 and P2 reached `ATTACHED`. This is Host software evidence only; it is
not USB, AP, RF, power-cut, or multi-device HIL.

The first independent review then found an acceptance-gate false-green rather
than a production-path defect: the shell accepted relay-side submit counters
without hard-asserting P1 receive, ignored background-role exit status and
sanitizer diagnostics, and selected ephemeral ports through a bind-close-bind
race. The repaired runner now uses listener-owned port-0 binding, requires
P1's verified-hop marker, performs an explicit two-phase shutdown, checks all
four child statuses and every role log, and fails closed on timeout or orphan.

Root reran both the positive and negative paths. Strict and ASan/UBSan again
passed with the digest above and all four roles exited zero. The negative
self-test correctly rejected a forced P1 exit status `97` and a synthetic
`ERROR: AddressSanitizer` marker, then reported `NEGATIVE SELF-TEST PASS`.
The independent closure is
[the Host completion integrated E2E review](../reviews/2026-07-30-host-completion-integrated-e2e-review.md)
with **P0=0 / P1=0 / P2=0 GO**.

### 2026-07-30 POSIX direct-path socket boundary repair

The Portable Host review reproduced a fail-open path truncation in the POSIX
loopback bearer. macOS limits `sockaddr_un.sun_path` to 104 bytes, while the
bearer copied a longer configured path with `snprintf`. The kernel received a
truncated `.soc` path but teardown unlinked the original `.sock` path. A first
direct one-hop run could therefore pass and leave a stale listener path that
made the second run fail.

The bearer now rejects empty and non-representable socket paths at creation,
copies an exact NUL-terminated path only after the boundary check, and no
longer opens an unused descriptor when an existing server listener is reused.
The boundary regression proves:

- `sizeof(sun_path) - 1` bytes are accepted;
- `sizeof(sun_path)` and longer paths are rejected;
- the direct one-hop fixture uses one short `/tmp` path derived from process
  and scenario identity for creation, retry cleanup, and final cleanup.

Root built the two focused tests with strict warnings and ran both tests twice
without rebuilding in the normal tree and twice in the ASan/UBSan tree:

```text
posix_loopback_partial_read + v1_direct_1hop_e2e
normal:       2/2 PASS, then 2/2 PASS
ASan/UBSan:   2/2 PASS, then 2/2 PASS
```

### 2026-07-30 Portable Host SERVICE capacity atomicity repair

The installed public-API consumer exposed that a non-Domain first service
registration persisted the semantic SERVICE registry row but left the
SERVICE resource ledger at `used=0`. That contradicted the normative
first-registration atomicity contract and made the earlier four-Service
consumer result a false green.

The non-Domain Runtime now stages the NRS SERVICE row and only the
`RS_CAPACITY_SERVICE` row in one FULL transaction. The public handle, live
service count, and live resource ledger are published only after commit OK.
The exact writer allowlist is `0x000080040`
(`SPINE_SERVICE_MARKER | RS_CAPACITY_SERVICE`); it does not grant access to
the other ten capacity kinds. Restart restores the SERVICE registry before
the delivery/capacity scan, so the durable service count can be validated
against `used/high_water`.

When four configured service slots are occupied, the first rejected fifth
registration persists SERVICE `blocked=1` in its own FULL. A later rejection
while already blocked performs no write. Fault tests cover NRS/capacity first
registration and the full-capacity blocked write independently:

- PUT and commit I/O failure leave live and cold-restart state unchanged;
- `COMMIT_UNKNOWN` with durable OLD fences the live instance and restarts
  unregistered/unblocked;
- `COMMIT_UNKNOWN` with durable NEW fences the live instance and restarts with
  the complete registered or blocked state;
- all other capacity kinds remain byte-identical in every case.

Root independently configured new normal and sanitizer trees and observed:

```text
focused Runtime/allowlist/capability/family:
  normal:       6/6 PASS
  ASan/UBSan:   6/6 PASS
fresh tests-OFF installed public consumer:
  SQLite OFF:   PASS
  SQLite ON:    PASS (provider destroy/recreate and disk reopen)
  Domain ON:    PASS (unpublished profile fails closed)
```

The independent Portable Host source review reports local P0=0/P1=0 for this
surface. Immutable-commit Linux/macOS CI and release clean-room evidence are
still separate promotion gates.

### 2026-07-30 MFDT repaired single-engine contract

The repaired private MFDT engine now has one exact interpretation: one engine
owns one active sender or receiver transfer on both Host and ESP profiles.
MFN1 uses `0x34..0x35`, MFDT uses `0x36..0x43`, and no void-allocation alias is
accepted. NRC1 replay is scoped by `(session_generation, request_id)`.

The direct suite covers canonical ABORT/ABORT_ACK/NM30 transitions, expiry and
retention boundaries, checked deadline arithmetic, semantic restart
validation, session-generation atomic reset, caller metadata cold restart,
acceptance evidence, exact second-transfer rejection, and startup-only
allocation. Root independently rebuilt the current shared source in two fresh
trees:

```text
normal:       27/27 PASS
ASan/UBSan:   27/27 PASS
```

This closes the single-engine software tranche only. MFDT remains private,
default-OFF, and Proposed. The exact four-slot Host coordinator and its shared
store/scheduler acceptance are a separate active tranche. Physical ESP
power-cut evidence remains `NOT_RUN`.

The first Host-coordinator tranche now provides the private typed store port
and exact reference provider. It enforces 32 committed keys, 383372 committed
logical bytes, 50075 serialized FULL staging bytes, two PUT row images within
four operations, and the 34-row/433447-byte begin+final union. The reference
provider builds the complete final view in an inactive fixed bank and only then
publishes it, so second-operation failure and rollback cannot expose a partial
view. It also provides prefix snapshot iteration, FULL/snapshot exclusion,
fixed-bank reuse, deterministic IO faults, and fail-closed CU OLD/NEW.

Root independently compiled the store port/provider/test with strict C11 and
ran both normal and ASan/UBSan binaries successfully. The frozen tranche's
expanded suite is **7/7 PASS** in each mode; Clang static analysis reports zero
findings. Atomic-provider-impossible CU mixed states remain assigned to the
independent coordinator mutation provider and are not silently treated as
OLD/NEW.

### 2026-07-30 OSS release independent audit

The independent package/release audit found no P0, but the candidate remains
NO-GO with four P1 findings:

1. the intended source is not yet one immutable clean commit;
2. that exact commit has no remote Linux/macOS/ESP/release-dry-run evidence;
3. the D3-S4 oracle is a 51.48 MiB non-hermetic CI/resource risk;
4. the README described an already-implemented four-Service installed
   consumer as future work.

The README now separates local-green implementation from immutable/remote
promotion evidence, and release examples use the current `v0.1.0` series.
The D3-S4 oracle is being compacted without reducing its 468-vector semantic
coverage. Immutable release evidence cannot be produced until all intended
changes are coherently committed.

The audit's package-policy and local-junk P2s are also closed in source:

- installed CMake compatibility is `SameMinorVersion` for `0.x` and
  `SameMajorVersion` for `1.0+`; a dedicated CTest proves `0.1.x` patch
  compatibility and rejects `0.2.x`/`1.x` for the current package;
- issue/release examples use `v0.1.0` or a shell release variable;
- root compiler/self-test scratch (`-`, `-.su`, `tmp-a2/`) is explicitly
  excluded from source control, while the D3-S4 self-test producer is being
  moved to an OS/build temporary directory.

### Physical-device inventory

Only the macOS Bluetooth/debug serial endpoints were present. No ESP USB serial
device was detected, so all physical HIL remains `NOT_RUN`.

### 2026-07-31 direct one-hop restart/loss determinism repair

The whole-tree run reproduced one persistent failure in
`v1_direct_1hop_e2e`: the controller could finish and remove its Unix listener
while the endpoint was still rebuilding its Platform and reopening the Bearer.
The endpoint then correctly returned transient `NINLIL_E_WOULD_BLOCK`, but the
fixture treated that scheduling race as a Runtime failure. The data/receipt
loss cases also advanced simulated time on every tight controller loop, so a
busy runner could expire the application deadline before the peer process was
scheduled.

The fixture now uses a two-way Unix `socketpair` for restart coordination.
After receiving the restart command, the endpoint destroys/recreates its
Runtime, reattaches the Service, and acknowledges successful Bearer reopen
before the controller may continue. The acknowledgement has a bounded 15
second poll timeout. Loss tests advance the trusted test clock once by the
amount needed to cross the retry timeout; they no longer manufacture repeated
deadline progress while racing the other process.

Freshly rebuilt focused evidence:

```text
v1_direct_1hop_e2e:
  normal, 10 consecutive runs: PASS
  ASan/UBSan, 4 consecutive runs: PASS
  restart, data loss, receipt loss, timeout, duplicate and ordinary paths
```

This is Host test determinism evidence only. It does not replace ESP USB/RF
restart or power-cut HIL, which remains `NOT_RUN`.

### 2026-07-31 MFDT Runtime instance-owner foundation rerun

The private/default-OFF MFDT candidate now has one owner per public Runtime
instance, an exact four-slot Host coordinator, and a filter adapter over the
already-open Runtime Storage handle. The ordinary Runtime step reaches this
owner, but intentionally returns `NINLIL_E_UNSUPPORTED` while the canonical
carrier, ingress, remote callback/evidence, and Receipt path are not connected.
It does not send an empty single-frame Application or synthesize completion.

Root configured two fresh build trees from the shared worktree and reran the
owner, coordinator, media-CU, capability, private-build, and Host-profile
boundary tests:

```text
normal:       8 selected executions / 6 unique tests PASS
ASan/UBSan:   8 selected executions / 6 unique tests PASS
```

The first aggregate attempt also exposed that the MFDT acceptance self-test
mutated three tracked authority files in place and restored them afterward.
Normal and sanitizer CTest processes could therefore race, and a concurrent
developer edit could be overwritten. The self-test now passes mutated strings
directly to parameterized validators and never writes the work record,
dedicated CMake authority, or root `CMakeLists.txt`. Four simultaneous
self-tests passed with identical before/after SHA-256 values for all three
files. After building the complete test inventory, the fresh aggregate rerun
was:

```text
normal:       38/38 PASS
ASan/UBSan:   38/38 PASS
```

The tests cover two independent Runtime owners, 4096-byte transfers in all four
Host slots, exact fifth-transfer capacity rejection, and a separate Runtime
holding a 32768-byte transfer. This closes only the instance-owner foundation.
Public `ninlil_submit()` long-data E2E, mixed Runtime/MFDT restart inventory,
ordinary ingress demux, remote application handoff/evidence, ESP exact-one
owner, MF-O08, and physical HIL remain open.

Root integration also found that “mixed Runtime/MFDT restart inventory” is not
correctly closed by extending the existing scanner. The accepted Runtime
namespace permits at most 4096 bytes per value and treats a larger
`iter_next` requirement as corruption without reread, while MFDT requires
34983-byte active records and a 15020-byte NRC1 row. The current same-handle
owner is therefore only a private test seam.

The candidate repair now uses a separate deterministic MFDT sidecar namespace
and keeps the Foundation scanner unchanged. ADR-0021 and docs/34 freeze a
36-byte derived namespace, an exact full-base `NMS1` binding row for collision
detection, sidecar-prearm then Foundation-FULL ordering, restart
cross-check/orphan cleanup, and Bearer→sidecar→Foundation teardown.

The first implementation slice is now executable. The Runtime owner opens the
separate handle, validates/creates `NMS1`, recovers Host rows, and closes in the
required order. Real SQLite cold restart/isolation/collision and deterministic
in-memory binding FULL `COMMIT_UNKNOWN` `ABSENT/NEW/PARTIAL/EXTRA/THIRD` tests
pass in fresh normal and ASan/UBSan builds (three selected executions in each,
including the private-build fixture). The synchronized Python/Node/C storage
authority suite is 10/10 PASS with 111 vectors.

This closes the sidecar bootstrap/profile slice only. Public-submit
pre-arm↔Foundation reconciliation, ordinary carrier/ingress and remote apply,
ESP exact-one ownership, independent implementation review, and physical HIL
remain open. No scanner/allowlist weakening or release-state promotion is
allowed as a shortcut.

## Integration exit order

1. Freeze each active implementation lane and rerun its exact normal,
   sanitizer, fault/restart, tests-OFF/install, and ESP evidence commands.
2. Run an independent review of each high-risk lane and close all P0/P1
   findings without weakening tests or authority boundaries.
3. Run the whole-tree normal and sanitizer matrices from fresh build
   directories.
4. Run package, documentation, license, dependency, workflow, SBOM, and
   security gates.
5. Create one coherent commit, rerun immutable commit-tree release gates, then
   push.
6. Keep the release state below `HIL_VERIFIED` while physical evidence is
   absent.
