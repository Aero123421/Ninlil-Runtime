# MFDT full SPEC acceptance independent review — NO-GO

> **Superseded for current status (2026-08-01):** this is the historical
> 2026-07-30 NO-GO snapshot. The repaired design's current independent verdict
> is [2026-08-01 MFDT v1 SPEC_ACCEPTED review](2026-08-01-mfdt-spec-accepted-review.md).
> Findings below are preserved as audit history.

Date: 2026-07-30  
Auditor: Codex independent review  
Scope: ADR-0021, its four authority systems, U5/U6 freeze non-interference,
reference documents, private/default-OFF implementation evidence, and the
`PROPOSED -> SPEC_ACCEPTED` gate  
Verdict: **NO-GO — ADR-0021 must remain Proposed**

## 1. Snapshot and claim boundary

The reviewed working snapshot was based on:

- branch: `codex/runtime-completion`
- HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`
- MFDT vector SHA-256:
  `635f71c5833ee150376e8fd9edde8c18e3c9ca73ce193d0600de62801243959b`
- authority-map SHA-256:
  `ef32126ad828d57001792022d53ec1f4a6a4519b0bab48a930b6d7f3806c48f4`
- vector schema/status/count:
  `ninlil.multi-frame-durable-transfer.spec.v1` /
  `PROPOSED_SPEC_ONLY` / 93

The worktree contained other agents' uncommitted work. This review therefore
anchors the exact MFDT authority hashes above and does not represent unrelated
dirty files as part of a commit-level acceptance claim.

This is a design acceptance review under
[`docs/34-v2-runtime-fabric-completion.md`](../34-v2-runtime-fabric-completion.md).
`SPEC_ACCEPTED` is a design claim only. Implementation, target, HIL, and release
support remain separate claims. Implementation defects below do not replace the
S1–S6 decision, but they invalidate the current software-candidate evidence and
show where the present tests are incomplete.

## 2. Executive verdict

Promotion is blocked independently by both of the following:

1. **The normative design has two P0 contradictions:** NRC1 says every slot
   binds a session generation but allocates no slot field for it; reservation
   expiry also requires an `NM30 ABORTED/EXPIRED` record that the closed NM30
   invariant cannot represent.
2. **The normative design has unresolved P1s:** version allocation,
   Host-four ownership/resource bounds, reference-document consistency,
   promotion-ON scope, and NRC1 length are not exact and mutually consistent.

Current count on this frozen snapshot:

| Surface | P0 | P1 | P2 | Result |
| --- | ---: | ---: | ---: | --- |
| S1–S6 design/spec | 2 | 6 | 3 | **NO-GO** |
| private implementation candidate | 6 | 6 | 0 | software-candidate closure invalid |

`MF-O06` cannot close. `MF-O02` must not remain represented as fully closed
software-candidate evidence until the implementation findings are repaired and
re-reviewed.

## 3. Fresh verification performed

All commands were run from a fresh review build directory. Green existing gates
are recorded honestly; they do **not** override the semantic findings below.

| Verification | Result |
| --- | --- |
| generator `--check` / `--self-test` | PASS / PASS |
| Python gate `--check` / `--self-test` | PASS 93/93 / PASS |
| Node gate `--check` / `--self-test` | PASS 93/93 / PASS |
| acceptance gate `--check` / `--self-test` | PASS (`systems=4`, `cmake_tests=10`) / PASS |
| freeze non-interference `check` / `self-test` | PASS / PASS |
| fresh strict normal focused CTest | **26/26 PASS** |
| fresh ASan+UBSan focused CTest | **26/26 PASS**, sanitizer finding 0 |
| physical ESP/RF/Wi-Fi/power-cut HIL | **NOT_RUN** |

Focused CTest command:

```sh
ctest --test-dir build-codex-mfdt-full-spec-review-normal \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure

ASAN_OPTIONS=halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir build-codex-mfdt-full-spec-review-asan \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure
```

The accepted U5/U6 surfaces remained byte-exact:

| Surface | SHA-256 |
| --- | --- |
| `docs/23-usb-radio-boundary.md` | `adaf5cd154adb3eb5f85d404e31894ee5f306351d6d1fa2a3d8c2ffd84536a34` |
| `docs/25-u5-cell-operating-assignment.md` | `ba62b2c7f4319c92c5b692b9c24747c27ee6e6d9809a5f1c2ebdad134a41e71a` |
| `docs/26-u6-transport-custody.md` | `f68b7008a62d3ae18f630babf88d2213ebf2946d4c77a37d8d95d164730edc59` |
| `docs/adr/0006-u6-transport-custody.md` | `d4ea04596d0fb0a1d802c4043f537c21c82da84cd5581bd0a215f53f286bc2bc` |

## 4. Normative design findings

### SPEC-P0-01 — NRC1 cannot bind each slot to a session generation

ADR-0021 explicitly says every NRC1 slot binds `session_generation`, prior
generation RESUME slots alone are reclaimed, and non-RESUME slots remain for
the transfer lifetime
([ADR-0021:350](../adr/0021-multi-frame-durable-custody.md)). The exact row
layout has only one generation at offset 24
([ADR-0021:402](../adr/0021-multi-frame-durable-custody.md)); the 204-byte slot
contains only request ID, digest, response type/length, and body
([ADR-0021:419](../adr/0021-multi-frame-durable-custody.md)).

The generator nevertheless asserts
`session_generation_bound_on_slot=True`, while `nrc1_slot()` emits no
generation bytes
([generator:970](../../tools/multi_frame_durable_transfer_spec_vector_gen.py),
[generator:1045](../../tools/multi_frame_durable_transfer_spec_vector_gen.py)).
Changing the single row-header generation relabels retained old-generation
non-RESUME slots and makes exact `(generation, request_id)` correlation
impossible.

**Minimal repair:** because NRC1 schema 1 is still Proposed, add a u32
`session_generation` to every occupied slot and make lookup identity
`(session_generation, request_id)`. One canonical layout is:

```text
0/8 request_id
8/4 session_generation
12/32 request_body_digest
44/2 response_message_type
46/2 response_body_length
48/160 response_body
```

This makes each slot 208 bytes, NRC1 value 15,020 bytes, NRC1 logical row
15,056 bytes, and one-transfer admission reservation 50,275 bytes. Recalculate
all namespace/Host aggregate/staging/wear constants and KATs rather than
retaining the old 14,732/14,768/49,987 values. Session advance must atomically
update active state plus NRC1, reclaim only prior-generation RESUME slots, and
reset the per-generation RESUME counter.

### SPEC-P0-02 — expiry cannot be represented by canonical NM30

ADR-0021 defines:

- wire abort reasons as `OPERATOR=1, SUPERSEDED=2, DEADLINE=3, POLICY=4`
  ([ADR-0021:771](../adr/0021-multi-frame-durable-custody.md));
- `NM30 ABORTED` as reason 1..4, abort generation 1..8, and non-zero actor
  ([ADR-0021:991](../adr/0021-multi-frame-durable-custody.md));
- mandatory reservation expiry as `NM30 ABORTED reason EXPIRED`
  ([ADR-0021:1284](../adr/0021-multi-frame-durable-custody.md)).

The generator then assigns `terminal_reason=0x8003` while retaining
`terminal_state=ABORTED`
([generator:3236](../../tools/multi_frame_durable_transfer_spec_vector_gen.py)).
`0x8003` is outside the ABORTED 1..4 domain and adjacent to the
CORRUPT_FENCED-only 0x8001/0x8002 domain. The vector also supplies no valid
abort generation or authority actor. Thus no 164-byte NM30 can simultaneously
satisfy the expiry transcript and the NM30 invariant.

This is a design P0, not an implementation-only issue. The current Python/Node
gates reproduce the same wrong value and therefore pass a self-consistent
contradiction.

**Minimal compatible repair:** because ADR-0021 is still Proposed and its
storage schema has not been accepted or released, reserve terminal-only
`EXPIRED=5`; keep TRANSFER_ABORT wire reasons 1..4 unchanged. Define:

- authority/user ABORTED: reason 1..4, generation 1..8, actor non-zero;
- automatic expiry ABORTED: reason 5, generation 0, actor zero;
- CORRUPT_FENCED: reason 0x8001 or 0x8002, generation 0, actor zero.

This changes no Accepted U5/U6 wire and needs no migration of an Accepted MFDT
store. A complete 164-byte expiry NM30 KAT must be RED before implementation
and GREEN before re-review.

### SPEC-P1-01 — HELLO `1..3` contradicts the independent MFN1 domain

[ADR-0021:43](../adr/0021-multi-frame-durable-custody.md) says HELLO min/max is
closed range 1..3 and selects the maximum intersection. The immediately
following table and prohibitions require selected control version exact 1 or 2
and forbid selected=3 inheritance
([ADR-0021:47](../adr/0021-multi-frame-durable-custody.md)).

Remove the 1..3 selected-catalog statement. MFDT admission must remain a
separate MFN1 v1 transcript bound to an Accepted selected version 1 or 2.

### SPEC-P1-02 — Host active=4 lacks a realizable bounded owner profile

The ADR repeatedly requires Host active max 4 and round-robin fairness
([ADR-0021:230](../adr/0021-multi-frame-durable-custody.md),
[ADR-0021:1107](../adr/0021-multi-frame-durable-custody.md)). It simultaneously
defines one exact 65,536-byte workspace and gives only the ESP/single-transfer
storage arithmetic:

- one active+NRC1 pair = `35,019 + 14,768 = 49,787` logical bytes;
- one terminal staging reservation raises this to 49,987;
- the stated committed namespace ceiling is 69,632 bytes.

Four maximum active transfers require at least 199,148 bytes before terminal
staging, which does not fit the only stated namespace bound. The spec does not
say whether 65,536 bytes is per transfer, per engine, or per Host owner; it
does not allocate four slots, define transaction serialization, or calculate
Host committed/staging maxima. There is no positive four-transfer KAT, fifth
transfer rejection KAT, or four-way round-robin trace.

Host=4 is a deliberate OSS/Host profile requirement and must **not** be reduced
to 1 to match the current code. Minimal repair:

1. keep a single-transfer engine primitive;
2. normatively define a Host owner/coordinator with four indexed transfer
   slots and exact transfer-ID routing;
3. define 65,536 bytes as **per active slot**, with exact aggregate owner RAM;
4. define the Host durable-store committed and begin/final staging ceilings,
   including whether terminal FULLs are serialized;
5. define one unpaid CHUNK_OFFER per peer and deterministic round-robin across
   all occupied slots;
6. add exact 4-pass/5-reject, slot reuse, two-direction, restart, and fairness
   vectors.

### SPEC-P1-03 — reference documents retain the rejected v3/re-freeze model

- [docs/34:459](../34-v2-runtime-fabric-completion.md) still calls MFDT a
  negotiated private control protocol v3 catalog and requires docs/06/23/25/26
  to be re-frozen.
- [docs/06:220](../06-versioning-and-compatibility.md) still describes full
  selected-catalog inheritance and a later docs/23/25/26 re-freeze.
- ADR Acceptance item 9 requires simultaneous docs/06/23/25/26 re-freeze
  ([ADR-0021:1205](../adr/0021-multi-frame-durable-custody.md)).
- ADR Decision forbids editing docs/23/25/26 and requires their Accepted bytes
  to remain unchanged ([ADR-0021:47](../adr/0021-multi-frame-durable-custody.md)).

Update docs/34 and docs/06 to the independent MFN1 domain. Replace Acceptance
item 9 with byte-exact U5/U6 freeze non-interference plus updates only to
candidate-level reference documents. Do not edit docs/23/25/26.

### SPEC-P1-04 — promotion-ON semantics are neither allocated nor exact

The OFF profile is exact and fail-closed. However, the table at
[ADR-0021:546](../adr/0021-multi-frame-durable-custody.md) includes a
“verified physical-HIL promotion ON” row whose rule is only
“post-attestation adapter rule applies.” No accepted evidence schema, trust
anchor, rollback/revocation state, or exact replay rule exists.

For this SPEC acceptance, delete the semantic promise and mark promotion ON
**UNALLOCATED / outside the accepted profile**. A future Proposed amendment
must pass S1–S6 before adding it. `MF-O08` then remains an implementation,
target, HIL, and release blocker; it does **not** by itself block acceptance of
the exact promotion-OFF design.

### SPEC-P1-05 — NRC1 response length is contradictory

The slot layout permits response body length `0..160`
([ADR-0021:419](../adr/0021-multi-frame-durable-custody.md)), while the
canonical rules require non-empty slots to have `L in 1..160` and forbid
empty cacheable responses ([ADR-0021:445](../adr/0021-multi-frame-durable-custody.md)).
Change the slot field range to 1..160 for occupied slots; only an all-zero empty
slot may have L=0.

### SPEC-P1-06 — the independent semantic gate is CRC-centric

The Python gate's active-record validator checks magic and two CRCs, and its
NM30 validator checks framing and CRC only
([Python gate:2068](../../tools/multi_frame_durable_transfer_spec_gate.py)).
The positive path then checks transfer ID and hashes but not the complete
canonical field/state invariants
([Python gate:2723](../../tools/multi_frame_durable_transfer_spec_gate.py)).
Its self-test mutates bytes without adding the repaired-CRC semantic corruption
class that a canonical reader must reject
([Python gate:3739](../../tools/multi_frame_durable_transfer_spec_gate.py)).

S4 requires an independent semantic oracle, not only generator agreement and
CRC integrity. Add closed NM3S/NM3R, NRC1, and NM30 validators plus permanent
mutants for reserved bits, owner/state, embedded OPEN bind/geometry, bitmap,
reservation/publication/abort invariants, NRC1 slot generation, and all
terminal-class cross-products after repairing their CRCs.

### P2 editorial/authority drift

1. `MF-BUDGET-FULL-MAX-WITH-REQID` correctly pins 77/67, but its note says
   daily `136/116`; it must say `154/134`
   ([generator:1883](../../tools/multi_frame_durable_transfer_spec_vector_gen.py)).
   Add an independent assertion/mutant for the explanatory arithmetic.
2. `docs/work/2026-07-29-multi-frame-durable-transfer-spec-repair.md` still
   says selected 1/2/3, 68/58 and 136/116, and 83/83 vectors. It must be
   corrected or explicitly superseded.
3. README says MF-O08 must close before formal ADR acceptance. That conflicts
   with the S1–S6 design-only state model. It should say MF-O08 blocks
   TARGET/HIL/release while the accepted design, if promoted later, is
   promotion-OFF only.

## 5. Private implementation findings

These findings do not redefine S1–S6. They prove that the current private code
and GREEN software rows cannot be used as implementation-complete evidence.

### IMP-P0-01 — a second transfer receives another transfer's OPEN_ACCEPT

`receiver_on_open` notices a different transfer ID but only returns BUSY when
`active_count >= active_max`. In Host mode `1 < 4`, so it falls through to the
“same transfer late path” and emits the first transfer's BIND52
([engine:1510](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).
The sender path independently rejects every second transfer because the engine
contains one workspace
([engine:982](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).

Independent probe output:

```text
sopen1=0 sopen2=0
rx1=0 type1=0x41 bind1=01
rx2=0 type2=0x41 bind2=01 expected_tid2=02 active=1
sender second=-4 active=1 host_max=4
```

This is false identity/custody, not merely missing throughput.

### IMP-P0-02 — arbitrary ABORT is accepted and ACK layout is wrong

`receiver_on_abort` performs no exact length, BIND52, reason, reserved,
authority actor, or generation validation
([engine:2062](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)). It then returns a
60-byte `ABORT_ACK`, while the normative body is 92 bytes with a tombstone
digest.

Independent one-byte-body probe:

```text
invalid_abort rc=0 type=0x4d body_len=60 active=0
probe_exit=3
```

An unbound one-byte request can therefore terminate durable receiver custody.

### IMP-P0-03 — every generated NM30 terminal is non-canonical

`build_nm30` writes `terminal_reason`'s argument into offset 60 as if it were
terminal state, then writes a 32-bit value at offset 62, overlapping
`terminal_reason` and `abort_generation`
([engine:769](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)). It does not populate
COMPLETE evidence/digest, ABORT authority, or retention epoch. Call sites pass
retention duration as the retention monotonic anchor.

Expiry probe output:

```text
len=164 state@60=2 reason@62=0 abort_gen@64=2147680256
epoch_zero=1 anchor@148=86400000
bytes60_68=0002000080030000
```

The stored record has a valid CRC over invalid semantics. No runtime NM30
validator rejects it.

### IMP-P0-04 — expired and overflowing OPENs are accepted

The receiver does unchecked `now_ms + 300000`, ignores the OPEN effect
deadline after layout validation, and does not apply same-epoch earlier-bound
logic ([engine:1537](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).

Independent probe output:

```text
expired_same_epoch rc=0 type=0x41 reject=0 active=1
reservation_overflow rc=0 type=0x41 reject=0 active=1 not_after=299899
probe_exit=3
```

### IMP-P0-05 — restart decoder accepts semantically invalid durable records

`record_unpack` validates magic, lengths, and CRC only
([record:96](../../src/runtime/mfdt_v1/mfdt_v1_record.c)). It does not enforce
owner/state closed sets, key/magic/transfer binding, reserved zero, field
invariants, embedded OPEN equality/digest/geometry, bitmap bounds, or terminal
active-code prohibition. `load_active_from_store` does not add the required
complete validation.

After changing state to 255 and recomputing both CRCs:

```text
semantic_invalid_record rc=0 owner=1 state=255
probe_exit=3
```

### IMP-P0-06 — retention GC succeeds immediately

`retention_gc` loads NM30 and immediately deletes NM30+NRC1 without validating
the terminal record, epoch, anchor, or elapsed retention
([engine:2269](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)). Existing tests
currently make this immediate deletion a success expectation. An independent
completion probe with `now=1000` and retention `86400000` returned:

```text
immediate_gc=0 nm30_after=-5
```

This destroys the required late-duplicate evidence before its retention
contract permits it.

### Implementation P1s

1. The mandatory mid-transfer local-clock epoch-change fence/NM30 path has no
   engine implementation; `local_clock_epoch` is only copied into records.
2. The claimed caller-owned/no-heap-growth profile is contradicted by lazy
   `calloc`/`heap_caps_calloc` in `mfdt_v1_target_alloc.c`, engine scratch,
   spine context, and ESP store bulk buffers.
3. `sender_open` hard-codes origin/event/source/target/service/text/deadline
   instead of accepting the ApplicationData identity and deadline required by
   the generic manifest contract
   ([engine:940](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).
4. After validating `TRANSFER_ACCEPT`, the sender changes state but does not
   copy receiver evidence ID, acceptance generation, or acceptance digest into
   the durable sender record
   ([engine:1406](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).
5. Session-generation advance increments volatile config before FULL, has no
   rollback, updates NRC1 without the active record in the same FULL, and does
   not reset `last_resume_query_generation`
   ([engine:2457](../../src/runtime/mfdt_v1/mfdt_v1_engine.c)).
6. `MF-O02 CLOSED_SOFTWARE_CANDIDATE` and the GREEN software rows in
   `docs/work/mfdt_v1_acceptance_matrix.json` overclaim the code above. They
   must be reopened/downgraded or re-earned after repair.

## 6. Why the existing green tests did not prove acceptance

The 26 focused normal and sanitizer tests are useful regression evidence, but
they omit the exact negative boundaries above. Several spec gates compare an
artifact generated from the same authority that introduced the contradiction.
For example, Python and Node both hard-pin ABORTED/0x8003 rather than
independently applying the NM30 invariant.

Therefore “26/26 PASS” and “93/93 PASS” mean that the present implementation
and generated artifacts are self-consistent on covered cases. They do not mean
P0/P1/P2=0 or `SPEC_ACCEPTED`.

## 7. Mandatory RED acceptance tests before repair

The following tests must first fail against the current snapshot.

### Design/vector REDs

1. per-slot NRC1 generation byte KAT, two-generation same-request-ID
   correlation, prior-generation RESUME-only reclaim, and retained non-RESUME
   slot generation preservation;
2. full 164-byte `NM30 ABORTED/EXPIRED` canonical KAT, including CRC;
3. NM30 terminal-class cross-product:
   COMPLETE, authority ABORT reasons 1..4, automatic EXPIRED reason 5, and
   CORRUPT 0x8001/0x8002;
4. selected-control version 3 rejection with MFN1 v1 admission over selected
   version 1 and 2 positive cases;
5. Host four maximum-size active transfers accepted, fifth rejected with
   mutation 0, aggregate RAM/store bounds exact;
6. four-slot deterministic round-robin and one-unpaid-offer-per-peer;
7. ESP first active accepted and second rejected;
8. occupied NRC1 L=0 rejected; empty all-zero slot accepted;
9. promotion-ON unallocated/unsupported while promotion-OFF is exact;
10. corrected 77×2=154 and 67×2=134 explanatory arithmetic mutation.

### C implementation REDs

1. two, four, and fifth distinct transfer OPEN routing; no cross-BIND52 reply;
2. ABORT length 0/1/75/77, wrong BIND52, reason 0/5, zero actor,
   generation 0/gap/rollback/wrap, and reserved-nonzero rejection;
3. exact 92-byte ABORT_ACK and tombstone digest replay;
4. canonical COMPLETE, ABORTED, EXPIRED, and CORRUPT NM30 encode/decode KATs;
5. same-epoch deadline before/equal/after, different epoch no-compare,
   `now+300000` overflow, and mutation-0 rejection;
6. every NM3S/NM3R header field mutation with repaired CRC still rejected when
   semantic invariants fail;
7. retention before/equal/after boundary and epoch mismatch;
8. epoch change before READY, READY-before-handoff, and post-handoff;
9. allocator trap proving no allocation after admission/start, or an amended
   exact pre-reserved allocator profile accepted through S1–S6;
10. caller-provided origin/event/runtime/service/text/deadline round-trip;
11. four-slot crash/restart/CU matrix and 10,000 interleaved lifecycle run.

Physical power-cut, RF, and Wi-Fi HIL remain **NOT_RUN** and belong to later
TARGET/HIL promotion gates.

## 8. Minimal repair order

1. **Normative P0 first:** add per-slot NRC1 session generation and allocate
   terminal-only EXPIRED=5; close both with RED byte KATs and recompute every
   affected bound.
2. **Normative consistency:** remove selected=3 inheritance; update docs/34,
   docs/06, ADR Acceptance, work record, and README while preserving
   docs/23/25/26 byte-exact.
3. **Host=4 exact profile:** specify four-slot coordinator, per-slot workspace,
   aggregate RAM/store/staging ceilings, routing, fairness, and exhaustion.
4. **Promotion boundary:** accept only OFF; mark ON unallocated and keep
   MF-O08 open for target/HIL/release.
5. **Authority repair:** regenerate vector/C authority and add independent
   semantic assertions/mutants for every repaired invariant.
6. **Canonical codec/validator layer:** one NM3/NM30/NRC1 encode/decode
   authority used by engine and restart scan.
7. **Engine repair:** deadline, ABORT, terminal, retention, epoch-change, and
   caller-provided manifest metadata.
8. **Host coordinator:** four slots over single-transfer engines with exact
   transfer-ID routing and round-robin.
9. **Fresh verification:** normal + ASan/UBSan, full crash/restart matrix,
   default-OFF/noninstall, pinned ESP compile/map, then an independent review.
10. Only after P0=P1=P2=0 may ADR status, compatibility matrix, MF-O06, or
    software-candidate evidence be promoted.

## 9. MF-O08 decision

**MF-O08 does not inherently block design `SPEC_ACCEPTED`.** It blocks
promotion-ON implementation, TARGET_CANDIDATE, HIL_VERIFIED, default-ON, and
release support.

That conclusion is valid only after ADR-0021 is changed to accept the exact
promotion-OFF profile and explicitly mark promotion ON unallocated. The current
undefined promotion-ON row is itself an S3 P1 and must not be accepted.

The present promotion verdict remains **NO-GO** for the independent normative
P0/P1 findings above, regardless of MF-O08.
