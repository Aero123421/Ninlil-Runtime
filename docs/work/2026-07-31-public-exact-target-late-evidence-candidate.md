# Public exact-target late-evidence and MFDT fail-closed candidate

Date: 2026-07-31

Status: **HOST NORMAL + ASAN/UBSAN PASS / PHYSICAL HIL NOT_RUN**

Authority: normative chapters 12–14 and 16 plus Proposed ADR-0027

## Outcome

This tranche makes bounded exact-target evidence summaries and counters
observable and restart-stable through the public Runtime query surface. It
also repairs the private NTS3 record so that a logical MFDT payload is not
confused with inline single-frame bytes.

MFDT is still a private/default-OFF candidate. Until its worker and durable
custody are connected to the ordinary public Runtime scheduler, an admitted
MFDT-shaped transaction now waits fail closed instead of being transmitted as
an empty single-frame `APPLICATION` message.

No application-specific vocabulary was added to the portable Core.

## Public exact-target evidence

`ninlil_target_snapshot_t` now exposes bounded, target-local:

- late-evidence and counter-saturation flags;
- valid, duplicate, raw-overflow, and late evidence counters;
- the existing target-local latest evidence, outcome, reason, and attempts.

Receipt reduction binds both the source target and attempt to the exact durable
target. A wrong-target crossing cannot fall back to the first target.
Higher-stage, lower-stage, duplicate, and late material update only the matched
target. Transaction-level latest evidence is an aggregate maximum and is not
projected into another target. Terminal outcome and reason remain monotonic.

The target evidence summary, last material fingerprint, ingress sequence, and
counters are encoded in NTS3 and survive cold restart. Public ABI manifest,
golden output, repeatability, drift, C11, C++17, and installed-consumer coverage
were updated for the six added snapshot fields.

## NTS3 logical/inline payload split

NTS3 private schema 1.1 stores:

- `payload_length`: logical ApplicationData length;
- `inline_payload_length`: bytes owned inline by the Foundation record.

Valid shapes are:

- single-frame route: logical equals inline and is at most 926 bytes;
- MFDT route: logical is 927–32768 bytes and inline is zero.

The codec fails closed on inconsistent route/length combinations and never
uses the logical MFDT length as an inline copy/read length.

## MFDT scheduler fence

When private MFDT is compiled and an MFDT-shaped transaction reaches
`ninlil_runtime_step()` before the public worker is connected, the scheduler:

- returns `NINLIL_OK` and reports `more_work=1`;
- keeps the transaction `ADMITTED_READY + pending_dispatch`;
- does not prepare an attempt;
- does not acquire a Tx permit or call the Bearer;
- does not increment attempt/retry counters or record revision;
- does not apply deadline or terminal mutations, even after the effect
  deadline has elapsed;
- restores the same waiting state after cold restart.

The bearer send paths contain the same guard as defense in depth. A 926-byte
single-frame negative control continues through the normal path. The private
MFDT route selector also now supplies `session_generation`, which was
previously omitted and caused admission to reject a valid public selection.

This fence is not MFDT completion.

## Adjacent invariant repairs

The complete baseline run exposed three adjacent regressions:

1. the direct durable-allowlist fixture constructed a target without a queued
   delivery phase;
2. EventFact discard changed target outcome/reason without making target
   delivery/outcome phases terminal;
3. the legacy receipt catch-up path updated only the aggregate transaction and
   did not project completion into the exactly matched target.

The fixtures/reducers now preserve the target-level durable invariants.
The direct one-hop restart fixture was independently stabilized with a
bidirectional restart channel and acknowledgement synchronization.

## Traceability identity

The normative heading renames retain their existing stable IDs. Only the two
new headings received new identities:

- `NIN-PR1-DOC13-026-S004` — durable record/version and restart;
- `NIN-PR1-DOC14-014-S005` — ADR-0027 exact-roster vectors.

`tools/traceability_coverage_v2_materialize.py` then refreshed the reviewed
hashes/evidence. Both complete-coverage gates pass.

## Public exact-target repair addendum

The public query array contract and four-target acceptance boundary were
repaired without promoting ADR-0027 or substituting LAB rows for Canonical
Domain records.

### Extensible output-array stride

`ninlil_transaction_query()` now treats the first target element's
`struct_size` as the byte stride for the complete caller-provided array.
Before capacity comparison or projection it validates every supplied element
has the current ABI version and the exact same `struct_size`. Offset and
address arithmetic are checked. Projection writes only the known prefix;
unknown future tails and surplus elements remain unchanged.

Runtime and fresh installed-consumer tests cover:

- known-size and future-size arrays with capacities 2–4;
- a future-size `BUFFER_TOO_SMALL` call with no target-array mutation;
- mixed element sizes rejected before projection;
- correct projection of all four canonical targets with future tails
  unchanged.

### Four-target admission, completion, retry, and restart

The public Runtime test now admits one four-target DesiredState transaction
and verifies the atomic admission ledger:

- TARGET: used 4, reserved 0;
- EVIDENCE: used 4 SUMMARY units, reserved 32 RAW units;
- transaction reservation: 36 EVIDENCE units.

Caller-owned target buffers are destroyed immediately after admission.
Capacity 3 reports the required count without target mutation; capacity 4
returns the complete durable roster. The success path completes each target
independently, remains nonterminal until all four are satisfied, and restores
the same per-target outcome, attempt counts, and ledger after cold restart.

A separate definite-no-send path exercises round-robin retry isolation and
full exhaustion: exactly 32 Bearer attempts are made, eight for each target.
Every target then closes with
`RETRY_BUDGET_EXHAUSTED_NO_EFFECT`. The retained TARGET/EVIDENCE accounting is
unchanged after destroy/recreate, while `reservation_active` remains zero and
OUTBOX used/reserved remain zero. Terminal reservation cleanup and restart
therefore do not underflow any of those resource classes.

### Saturating evidence counters

Boundary tests cover valid, exact-duplicate, raw-overflow, and late-evidence
counters. For each counter, `UINT64_MAX-1` advances to `UINT64_MAX` without
the saturation flag; the next increment keeps the value at `UINT64_MAX` and
sets `evidence_counter_saturated=1`. The counter, flag, target semantics, and
terminal transaction result survive cold restart.

### Canonical raw evidence remains NO-GO

This repair does **not** materialize raw evidence history in NTS3. That would
be a false green:

- `src/runtime/runtime_v1_transaction_codec.h` defines NTS3 as a
  V1-LAB-private format and explicitly forbids sharing it with the docs/17
  Domain Store schema.
- `src/runtime/domain_schema1_startup_owner.h` keeps
  `NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY` at `0`.
- `ninlil_runtime_create()` therefore returns `NINLIL_E_UNSUPPORTED` before
  every Port call when Domain binding is enabled; complete D3-S1..S12, D4
  convergence, durable health reconstruction, and canonical operational
  writers are not yet connected.

The Normative requirement remains SUMMARY plus RAW slots `1..L` as physical
Domain `EVIDENCE_CELL` records. Exact duplicate detection over the complete
raw tuple history cannot be claimed until that Domain Runtime binding is
implemented and reviewed. The public query evidence-history item therefore
remains NO-GO rather than being represented by an NTS3 fingerprint or another
LAB row.

## Verification

Baseline focused build and tests:

```text
cmake --build build-public-mt-baseline --target \
  ninlil_v1_durable_allowlist_test ninlil_v1_event_mgmt_ledger_test \
  ninlil_v1_direct_1hop_e2e_test ninlil_v1_transaction_codec_test \
  ninlil_v1_runtime_spine_test ninlil_v1_runtime_delivery_test \
  ninlil_v1_runtime_capability_test ninlil_v1_runtime_family_test \
  ninlil_smoke_c11 ninlil_smoke_cxx17 ninlil_abi_contract_test \
  ninlil_abi_drift_test ninlil_abi_manifest_coverage_test -j4

ctest --test-dir build-public-mt-baseline --output-on-failure --timeout 120 \
  -R '^(v1_durable_allowlist|v1_event_mgmt_ledger|v1_direct_1hop_e2e|v1_transaction_codec|v1_runtime_spine|v1_runtime_delivery|v1_runtime_capability|v1_runtime_family|smoke_c11|smoke_cxx17|abi_contract_header|abi_contract_output|abi_contract_enum|abi_drift_check|abi_manifest_repeatable|abi_manifest_golden|abi_manifest_coverage)$'

17/17 PASS
```

The same build/test set under ASan/UBSan:

```text
17/17 PASS
```

Private MFDT-on focused normal and ASan/UBSan, each:

```text
cmake --build <mfdt-build> --target \
  ninlil_v1_runtime_capability_test ninlil_v1_transaction_codec_test -j4

ctest --test-dir <mfdt-build> --output-on-failure --timeout 180 \
  -R '^(v1_runtime_capability|v1_transaction_codec|mfdt_v1_unit_private|mfdt_v1_pipeline_private|mfdt_v1_media_cu_private|mfdt_v1_private_build)$'

normal:     6/6 PASS
ASan/UBSan: 6/6 PASS
```

Fresh tests-OFF installed consumer matrix:

```text
ctest --test-dir <build> --output-on-failure --timeout 180 \
  -R '^host_runtime_tests_off_installed_consumer(_sqlite|_domain_on)?$'

normal:     3/3 PASS
ASan/UBSan: 3/3 PASS
```

Post-addendum focused rerun:

```text
normal:
  v1_transaction_codec
  v1_runtime_spine
  v1_runtime_delivery
  v1_runtime_capability
  v1_runtime_family
  v1_posix_sqlite_restart_e2e
  v1_posix_platform_restart_e2e
  7/7 PASS

ASan/UBSan:
  v1_transaction_codec
  v1_runtime_spine
  v1_runtime_delivery
  v1_runtime_capability
  v1_runtime_family
  5/5 PASS

tests-OFF installed consumer matrix:
  normal 3/3 PASS
  ASan/UBSan 3/3 PASS
```

Complete traceability coverage:

```text
ctest --test-dir build-public-mt-baseline --output-on-failure --timeout 120 \
  -R '^traceability_complete_coverage_v2_(self_test|check)$'

2/2 PASS
```

## 2026-08-01 fresh-review blocking-finding repair

The fresh review found two public exact-target boundary defects.  This
addendum records their repair without changing the status of Canonical Domain
raw evidence, MFDT publication, Accepted ADRs, or physical HIL.

### Durable pre-send projection

`ATTEMPT_PREPARED` was durable, but `transaction_public_state()` did not read
it.  A transaction could therefore be observed as `TXN_READY` after the
attempt-prepare FULL commit and again after restart, although no new attempt
was allowed and the same attempt was awaiting its Bearer invocation.

The public projector now gives a nonterminal durable `attempt_prepared=1 /
send_observation_closed=0` exact precedence as `TXN_DISPATCHING`.  The second
predicate distinguishes the pre-send gate from the same active attempt after
a Bearer-return observation, which remains `TXN_AWAITING_EVIDENCE`.
DesiredState target projection applies the same rule to its exact active
target.  Because both query and list use the shared transaction projector, all
three public surfaces now agree:

- full `ninlil_transaction_query()` snapshot: `TXN_DISPATCHING / NONE`;
- exact target snapshot: `TXN_DISPATCHING / NONE`;
- `ninlil_transaction_list()` summary: `TXN_DISPATCHING / NONE`.

The normal commit test stops after prepare with Bearer send budget zero and
checks all three surfaces.  The committed-truth COMMIT_UNKNOWN recovery case
then cold-recreates the Runtime and checks the same three surfaces before any
send, proving the projection is based on recovered durable state rather than
volatile step state.

### Evidence-counter saturation single authority

Chapter 12 is now the explicit transition authority:

- `MAX-1 -> MAX` leaves `evidence_counter_saturated=0`;
- only a later attempted increment while that counter is already MAX keeps
  MAX and makes the flag sticky 1;
- flag 1 requires at least one of the four counters to equal MAX;
- flag 0 with a MAX counter is valid and recoverable.

Chapter 17 now delegates the transition meaning to chapter 12 and limits its
same-record rule to the exact snapshot shapes above.  NTS3 validation enforces
the one-way implication `flag 1 -> at least one MAX` without rejecting the
reachable `flag 0 + MAX` state.

The codec test includes positive encode/decode for both boundary snapshots,
negative encode and CRC-repaired negative decode for flag 1 with no MAX, and
unchanged-output-on-decode-failure.  Each of the four Runtime counters is also
driven to `flag 0 + MAX`, cold-restarted and publicly queried before the next
increment raises flag 1; the final saturated state is cold-restarted again.

### Verification

Fresh normal build:

```text
v1_transaction_codec      PASS
v1_runtime_delivery       PASS
v1_runtime_capability     PASS
3/3 PASS
```

Fresh ASan + UBSan build:

```text
v1_transaction_codec      PASS
v1_runtime_delivery       PASS
v1_runtime_capability     PASS
3/3 PASS
```

Fresh tests-OFF installed-consumer matrix, normal and ASan + UBSan:

```text
host_runtime_tests_off_installed_consumer
host_runtime_tests_off_installed_consumer_sqlite
host_runtime_tests_off_installed_consumer_domain_on
normal: 3/3 PASS
ASan + UBSan: 3/3 PASS
```

These results close only the two fresh-review software findings.  Canonical
Domain operational writers/raw evidence, MFDT public completion, Accepted
promotion, CI remote runners, and physical ESP/RF HIL remain unclaimed.

## Complete baseline snapshot and classification

The pre-repair complete run was:

```text
ctest --test-dir build-public-mt-baseline --output-on-failure -j8

386/395 PASS; 9 failures
```

Failures repaired and re-run in this integration:

- `v1_durable_allowlist` — exact-target durable invariant; now PASS.
- `v1_event_mgmt_ledger` — target terminal projection; now PASS.
- `v1_direct_1hop_e2e` — restart synchronization; now PASS.
- `traceability_complete_coverage_v2_self_test` — manifest stale; now PASS.
- `traceability_complete_coverage_v2_check` — manifest stale; now PASS.

Failures outside this tranche:

- `production_attachment_edhoc_c11_gate` — independent production-attachment
  work.
- `domain_scan_crossrow_d3s4_vector_oracle_self_test` — timed out during the
  parallel complete run; no domain-store code belongs to this tranche.
- `release_distribution_authority_gate` — concurrent `NOTICE` authority hash
  mismatch.
- `release_archive_cleanroom_gate` — the same concurrent release-authority
  mismatch.

The five repaired tests were re-run green, but the entire 395-test matrix was
not repeated after repair. Therefore this record does not claim a globally
green release suite.

## Honest remaining boundaries

- NTS3 persists only the most recent evidence-material fingerprint, not a full
  raw `EVIDENCE_CELL` history. An exact duplicate of an older, non-latest
  material cannot yet be recognized after newer material has replaced the
  fingerprint.
- Raw evidence-cell durable binding/materialization is not implemented.
- The public Runtime does not yet own MFDT scheduler pumping, session-bound
  ingress, or terminal projection.
- The current private MFDT spine is not yet Runtime-instance-local.
- MFDT production custody is not yet implemented over the Runtime Storage Port.
- Public long-ApplicationData E2E, concurrent transfer acceptance, ESP32-S3
  physical transport, and power-cut HIL remain `NOT_RUN`.
- ADR-0027 remains Proposed; this tranche must not be represented as
  Foundation or MFDT release completion.
