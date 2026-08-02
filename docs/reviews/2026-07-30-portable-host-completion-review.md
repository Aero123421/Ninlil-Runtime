# Portable Core / public Host Runtime independent completion review — 2026-07-30

Status: **local software candidate GO — P0=0 / P1=0 / P2=3**

Formal transition: **NO-GO**. Portable Core / Host Runtime remains
`SPEC_ACCEPTED` until the exact candidate is committed and the required
two-platform evidence is reproduced from that immutable commit.

This is a non-normative independent review record. It does not change an ADR,
the compatibility matrix, or a feature state by itself.

## 1. Scope and candidate identity

The review covers the public and installed Portable Core / Host Runtime surface:

- public C headers and the 14 exported Runtime API entry points;
- the installable CMake target `Ninlil::runtime`;
- bounded in-memory state and caller-supplied platform operations;
- memory and POSIX SQLite persistence;
- service registration, submission, deduplication, query/list, capacity,
  metrics, stepping, delivery completion, and restart behavior;
- a single physical node hosting several application Services;
- tests-OFF external-consumer installation and linking;
- public payload and role boundaries.

Private Wi-Fi, physical radio, relay, multi-parent, multi-frame transfer, target
execution, and hardware-in-the-loop verdicts are outside this review. They are
not promoted by a passing Host Runtime result.

The working tree was changing and was not committed at review time. The
repository `HEAD` was:

```text
e756aa06d38fdf1b6b3f1722aa8daf5af032bd38
```

The reviewed uncommitted source snapshot is additionally identified by these
file hashes:

| File | SHA-256 |
| --- | --- |
| `include/ninlil/runtime.h` | `6bb0324092695a67ac4151a4f21699655b09aed095dc048a05aa2bc47c128920` |
| `include/ninlil/service.h` | `c3b7a855ee65160d5bad27ae0b85cfd52b680d180c9fec1aa8bf8c56a2bfdc8d` |
| `src/runtime/runtime_public.c` | `6a9e5d75b8994c909186befbccd802000410e596741ae4213e9ea2aed3fed35a` |
| `src/runtime/runtime_v1_spine_durable.c` | `df8567ac01e05f59e115118b56fb60c04af1047296a654d5492d730832e27af4` |
| `src/runtime/runtime_v1_capability.c` | `6795f36f1dfa995718ef008bff94858806f63c7b65c0f48c2ec7d7deb5da394e` |
| `src/runtime/v1_durable_allowlist.c` | `bad34f2112e557b06a6de30ec82cfe6df5093a5c44cb3f49841fd93af48bb61c` |
| `tests/runtime/v1_runtime_spine_test.c` | `02f6a42fa9699eb54dcaa272f97fb5d4d1df635bec9e501a69cc2bf123c13c82` |
| `tests/cmake/installed_host_runtime_consumer/consumer.c` | `217c71e2d2a364bdd7eccc0632357bd0500a8544188e62ecb34a035872c5b146` |
| `cmake/installed_host_runtime_tests_off_smoke.cmake` | `9b2906f6ce5204f169932c1aeb9c14e34b275e8e23da4e9f33acc5201cf16eda` |

These hashes make the local evidence auditable, but they do not replace a fixed
commit. `HEAD` alone cannot reproduce the repaired candidate.

No external implementation CLI was used for this independent audit.

## 2. Executive verdict

| Decision boundary | Verdict | Reason |
| --- | --- | --- |
| Current macOS arm64 local software candidate | **GO, P0=0 / P1=0 / P2=3** | Public API, private source authority, installed tests-OFF consumer, memory/SQLite restart, strict build, and normal plus ASan/UBSan focused suites passed after the SERVICE-capacity repair. |
| `SPEC_ACCEPTED -> HOST_CANDIDATE` formal transition | **NO-GO** | The exact candidate is not an immutable commit; current Linux x86_64 evidence is absent; release clean-room/authority gates cannot pass against the stale `git:HEAD` archive identity. |

The second row controls repository status. A local software GO is not a formal
promotion and is not a release claim.

## 3. Public surface actually implemented

### 3.1 Runtime and resource contract

`include/ninlil/runtime.h:10-32` declares explicit finite limits for Services,
transactions, targets, durable outbox bytes, deliveries, event spool, result
cache, evidence, ingress, callbacks, state transitions, bearer sends, and
deferred tokens. `include/ninlil/runtime.h:34-46` configures one network role per
Runtime instance.

`include/ninlil/runtime.h:133-199` exposes these 14 public functions:

1. `ninlil_runtime_create`
2. `ninlil_runtime_destroy`
3. `ninlil_service_register`
4. `ninlil_submit`
5. `ninlil_offer_accept`
6. `ninlil_cancel_request`
7. `ninlil_event_resume`
8. `ninlil_event_discard`
9. `ninlil_transaction_query`
10. `ninlil_transaction_list`
11. `ninlil_delivery_complete`
12. `ninlil_runtime_step`
13. `ninlil_capacity_snapshot`
14. `ninlil_metrics_snapshot`

The implementation enforces owner-thread and callback-reentrancy rules and
handles `COMMIT_UNKNOWN` conservatively (`src/runtime/runtime_public.c:201-235`).
The Runtime copies platform-operation tables and performs bounded allocation
during create/destroy rather than allocating in steady-state API calls
(`src/runtime/runtime_public.c:238-307`,
`src/runtime/runtime_internal.h:289-380`).

### 3.2 Service contract and multiple Services on one node

`include/ninlil/service.h:10-43` gives each Service its own namespace, service
and schema identity, contract family, direction, evidence contract, payload and
target limits, inflight/rate limits, deadline range, retry timing, application
completion timeout, and deduplication window. Delivery and reconciliation
callbacks are public (`include/ninlil/service.h:45-98`).

The current design supports one Runtime/Endpoint with several independently
registered Services. The Host acceptance scenario in
`docs/work/2026-07-29-multi-service-node-host-acceptance.md:25-66` maps display
commands, access events, periodic temperature telemetry, and a temperature
query/response pair to separate Services on the same node. The public API is
therefore not fixed to a single application role.

The exact distinction is:

- **implemented:** several application Services registered in one Runtime,
  service-specific submission/delivery behavior, and composed query/response
  using paired Services;
- **application-managed composition:** periodic scheduling, subscription loops,
  and latest-state conventions;
- **not a public M1a primitive:** native capability discovery/search, a
  first-class event-subscription API, a first-class arbitrary LatestState API,
  or a single Runtime simultaneously owning several network roles.

`docs/04-runtime-api-and-storage.md:23-33` deliberately keeps one network role
per Runtime. Co-locating relay behavior with application Services therefore
belongs to a separate/private composition boundary and is not proven as a
public M1a capability by this review.

### 3.3 Request/response, events, state observation, and policy

The public surface implements transaction submit, query/list observation,
step-driven progress, delivery callback/completion, cancellation, and event
resume/discard. M1a request/response is composed from Services rather than
provided as a separate RPC object.

The following limits must remain explicit in user documentation:

- `ninlil_offer_accept` is reserved/unsupported in M1a;
- `ninlil_runtime_step` is the polling/event-loop integration point;
- an application cannot attach an arbitrary per-request `urgent` flag;
  scheduler class, quota, and reserved capacity are Service/site policy
  (`docs/02-application-contracts.md:185-202`);
- periodic transmission is scheduled by the application;
- transaction query/list is not a general-purpose application-state database.

### 3.4 ApplicationData and payload bounds

ApplicationData is represented as a transaction, descriptor snapshot, and
bounded byte payload. Opaque binary, UTF-8 text, preset identifiers, and sensor
values can all be application-level encodings; none requires domain vocabulary
inside the Runtime.

The accepted public single-frame path is limited to 926 payload bytes. The
boundary test accepts 925 and 926 bytes and rejects 927 bytes without admitting
a transaction (`tests/runtime/v1_runtime_capability_test.c:448-525`; see also
`docs/26-u6-transport-custody.md:99-109` and
`docs/09-roadmap.md:204-214`).

Durable multi-frame transfer exists only as a private/proposed area. It is not a
public M1a completeness claim and is outside this GO.

### 3.5 Installation and production-source authority

`CMakeLists.txt:940-1003` builds and installs `Ninlil::runtime` from an explicit
production source list. `cmake/ninlil_runtime_private_sources.cmake:11-62`
defines that source authority and keeps diagnostic/test-only selections
separate. Public headers do not require private test definitions.

A fresh Release configuration with tests disabled, Host Runtime enabled,
SQLite enabled, strict warnings enabled, and sanitizers disabled:

- built successfully in 65 build steps;
- reported `Total Tests: 0`;
- installed successfully;
- produced
  `/tmp/ninlil-ph-final-artifact-prefix/lib/libninlil_runtime.a`;
- produced archive SHA-256
  `6fdfde243df01c4a60478d695a3029ddfc5f52c3f5fa9c0f744ab766d6198237`.

All 14 public API symbols were present in the installed archive.

## 4. SERVICE capacity repair and closure

### 4.1 Reproduced defect

The original installed consumer accepted `used <= 4`. That assertion could pass
when four Services were registered but the Domain-OFF Runtime incorrectly
reported SERVICE `used=0`.

Replacing it with an exact expectation reproduced a RED result:

```text
initial service capacity mismatch: used=0
```

This was a real persistent-capacity defect, not only a weak test.

### 4.2 Repair

The reviewed repair:

- restores the durable Service registry before capacity validation;
- makes first unique registration reserve and commit the SERVICE ledger in the
  same FULL storage transaction as the Service marker;
- adopts live state only after commit success;
- durably records the first true full-capacity rejection as blocked;
- converges I/O error and commit-unknown OLD/NEW restart outcomes;
- prevents same-handle re-registration from changing SERVICE usage;
- isolates the exact durable write allowlist to the Service marker and SERVICE
  capacity row for this operation.

Relevant implementation:

- `src/runtime/runtime_public.c:1726-1871`
- `src/runtime/runtime_v1_spine_durable.c`
- `src/runtime/runtime_v1_capability.c`
- `src/runtime/runtime_v1_capability.h`
- `src/runtime/v1_durable_allowlist.c`

The strengthened tests prove:

- exact SERVICE `used/high_water` values 1 through 4;
- idempotent same-handle re-registration;
- fifth registration rejected as FULL and still blocked after restart;
- first-registration I/O error and commit-unknown OLD/NEW convergence;
- blocked-row commit I/O error and commit-unknown OLD/NEW convergence;
- unrelated resource-capacity rows remain unchanged;
- external memory and SQLite consumers observe SERVICE `used=4` before and
  after a cold reopen.

Files:

- `tests/runtime/v1_runtime_spine_test.c`
- `tests/cmake/installed_host_runtime_consumer/consumer.c`
- `cmake/installed_host_runtime_tests_off_smoke.cmake`

This closes the capacity issue as a P1 finding in the reviewed local candidate.

## 5. Independent execution evidence

Environment:

| Component | Value |
| --- | --- |
| OS/target | macOS arm64, `arm64-apple-darwin25.5.0` |
| CMake | 4.3.4 |
| Ninja | 1.13.2 |
| Compiler | AppleClang 21.0.0 |
| OpenSSL | 3.6.3 |
| SQLite | macOS SDK SQLite |

### 5.1 Focused normal suite

Twenty selected tests covering the installed tests-OFF memory, SQLite, and
Domain-ON consumers; private subproject; ABI; Runtime lifecycle/bootstrap;
durable allowlist and self-test; Runtime spine/delivery/capability/family; and
POSIX storage/restart/shared conformance all passed:

```text
20/20 PASS
elapsed: 39.71 s
```

### 5.2 Focused ASan/UBSan suite

The same 20 selected tests passed with:

```text
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
20/20 PASS
elapsed: 41.42 s
```

Leak detection was disabled. Also, the nested installed-producer build
explicitly configured sanitizers OFF, which is retained below as P2-2.

### 5.3 Targeted capacity and allowlist

The exact capacity and allowlist subset passed in both normal and sanitizer
builds:

```text
normal:      4/4 PASS
ASan/UBSan:  4/4 PASS
```

### 5.4 Fresh tests-OFF external consumers

Fresh producer/install/consumer trees passed:

```text
Domain-OFF memory consumer:  1/1 PASS
Domain-ON memory + SQLite:   2/2 PASS
```

They registered four Services, submitted EventFact data, checked
dedupe/conflict, query/list, exact capacity and metrics, stepped the Runtime,
and reopened memory/SQLite state.

### 5.5 Direct one-hop regression

A separate P1 in the POSIX loopback test used a socket path derived from a long
build directory. On macOS, `sockaddr_un.sun_path` truncation produced a
different cleanup path and repeat execution failed.

The implementation now rejects overlong paths, and the test uses a bounded
`/tmp/ninlil-d1-<pid>-<scenario>.sock` path with a boundary case. Normal and
ASan/UBSan repeat runs, including `v1_direct_1hop_e2e` and
`posix_loopback_partial_read`, passed twice. No new socket artifact remained.
This finding is closed.

## 6. Active findings

### P2-1 — Installed archive exposes a broad internal symbol surface

The fresh installed static archive contained 653 global symbols beginning with
`ninlil_`. Fourteen are the documented public Runtime API; 78 global names
matched internal LAB/C3/C4/C5/C6 naming patterns.

This does not presently make those functions public API: the installed public
headers do not declare them, and a static linker only pulls referenced object
members. It does, however, make accidental use and future ABI/package hygiene
harder. A future tranche should use symbol visibility, object partitioning, or
an explicit exported-symbol audit so the installed artifact communicates the
same boundary as the headers.

Acceptance:

- generate the approved public-symbol set from installed headers/authority;
- fail packaging when an unintended callable global enters the installed
  archive, or document a deliberate static-archive exception;
- prove a normal external consumer remains linkable.

### P2-2 — Installed-consumer sanitizer and semantic depth are incomplete

The outer sanitizer CTest invokes a nested producer configured with
`NINLIL_ENABLE_SANITIZERS=OFF`. Therefore the external consumer exercises the
installed boundary during the sanitizer run, but its installed Runtime archive
is not itself sanitizer-instrumented.

The consumer also provides broad contract smoke coverage rather than an
independent semantic body for every terminal, callback, reentrancy, and
commit-unknown branch of all 14 public functions. Internal tests do cover those
production sources, so this is P2 evidence depth rather than an active P1
correctness failure.

Acceptance:

- add a sanitizer-enabled installed producer/consumer variant;
- add a bounded external negative/mutation matrix for callback reentrancy,
  terminal query/list, cancellation/event management, and restart outcomes;
- retain tests-OFF and no-private-header enforcement.

### P2-3 — Promotion authority presentation is ambiguous

`docs/34-v2-runtime-fabric-completion.md:1-29` labels itself
“Proposed — Normative candidate / docs-only”, while README and promotion
decisions use it as the completion authority. The platform rows in
`README.md:188-193` and `compatibility-matrix.json` may say `HOST_CANDIDATE`,
while the Portable Core feature row remains `SPEC_ACCEPTED` and Host promotion
is NO-GO.

These statements can coexist if platform capability and feature maturity are
separate axes, but the current presentation can be read as contradictory.

Acceptance:

- identify the accepted normative promotion authority explicitly;
- state that a platform row does not promote every feature using that
  platform;
- update README, compatibility matrix, and review record atomically when the
  Portable Core feature is promoted.

## 7. Closed findings

| Finding | Initial severity | Closure |
| --- | --- | --- |
| SERVICE capacity false-green and durable `used=0` defect | P1 | Exact external assertion reproduced RED; atomic durable accounting, FULL blocking, restart/error tests, and external memory/SQLite reopen evidence now pass. |
| Direct one-hop UNIX socket path truncation | P1 | Exact-length validation, short test path, boundary case, and normal/sanitizer repeat evidence pass. |
| Changelog still described the public Runtime as unimplemented | P1 documentation | The current Unreleased section and historical pre-V1 section now distinguish the implemented pre-release Runtime/SQLite candidate from pending physical HIL. |

## 8. Explicit nonclaims

This review does **not** claim:

- current Linux x86_64 evidence;
- physical USB, radio, Wi-Fi AP, flash power-cut, or soak verification;
- field SLO or regulatory approval;
- release support;
- first-class native discovery/search, subscription, or arbitrary latest-state
  APIs;
- native per-request priority or Runtime-owned periodic scheduling;
- public multi-frame transfer;
- one Runtime simultaneously owning several network roles;
- public completion of private relay, multi-parent, Wi-Fi, or physical radio
  paths.

The product-neutrality gate passed across 782 tracked text files with zero
forbidden-vocabulary hits. The public Runtime/Core sources contain no
application-specific domain model.

## 9. Formal promotion checklist

Before changing the Portable Core / Host Runtime feature from `SPEC_ACCEPTED`
to `HOST_CANDIDATE`:

1. Integrate the repairs into one immutable commit and record the exact SHA.
2. Rebuild from that commit in clean macOS arm64 and Linux x86_64 trees.
3. Run the strict normal and sanitizer suites on both platforms.
4. Build and run installed tests-OFF memory and SQLite consumers from the same
   commit.
5. Add or explicitly disposition the sanitizer-installed-producer P2.
6. Pass release distribution authority and archive clean-room gates against the
   committed tree.
7. Repeat an independent review from the immutable candidate.
8. Update README, compatibility matrix, completion authority, and review index
   in one status-only change.

At review time, the release subset produced:

```text
release_distribution_authority_gate:           FAIL
release_distribution_authority_gate_self_test: PASS
release_archive_cleanroom_gate:                FAIL
```

Both failed gates reported the same archive `NOTICE` hash mismatch while using
`git:HEAD`:

```text
got      48f0e0afc687fde4a9eaefdb094793270b0c20de5d2622a336a4031018efed2a
expected 7fe5c13ffc658808747eb361dd14ed17ea912a5e5fe4d8f7a5405bfbb6185319
```

This is the expected consequence of reviewing a moving uncommitted candidate.
It is a promotion blocker, not evidence that the repaired local Runtime failed
its functional tests. It must become green after the final commit; otherwise it
must be reclassified as a release defect.

## 10. Final decision

The Portable Core and public Host Runtime are substantially implemented and
locally coherent. The SERVICE-capacity and UNIX-socket P1 defects were
independently reproduced and closed. The reviewed macOS candidate is:

```text
LOCAL SOFTWARE CANDIDATE: GO
P0=0 / P1=0 / P2=3
```

The repository state decision remains:

```text
FORMAL HOST_CANDIDATE PROMOTION: NO-GO
FEATURE STATE: SPEC_ACCEPTED
```

The remaining formal blockers are evidence and release-identity work, not a
license to describe unimplemented public functionality as complete.
