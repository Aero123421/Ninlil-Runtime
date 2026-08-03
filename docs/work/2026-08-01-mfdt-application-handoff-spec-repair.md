# MFDT Application handoff specification repair

Date: 2026-08-01  
Status: **SPEC_ACCEPTED — specification repair complete; implementation remains incomplete**

## Promotion outcome

The initial independent review returned NO-GO findings across P0, P1, and P2.
The normative atomic pre-arm ordering, duplicate-target Runtime behavior, and
token terminology were repaired without adding another state machine or public
API.  A limited independent re-review then returned **GO — P0=0 / P1=0 /
P2=0**.  Fresh root verification passed all **116/116** required authority
vectors and **CTest 10/10**.

This closes the specification repair only.  The revised OPEN codec,
Application Service apply-to-Receipt bridge, cold-restart reconciliation,
ESP32-S3 execution, physical HIL, and release support remain incomplete.

## Outcome

The Host Runtime transport reaches a verified receiver `READY`, but the
previous Accepted MFDT profile could not reconstruct the original Application
delivery after a cold restart.  This amendment closes that normative gap before
Application Service apply, evidence, Receipt, or public long-payload support
is implemented.

This repair must stay small: extend the existing canonical OPEN and the
existing Foundation transaction correlation.  Do not add another durable
binding row, another control exchange, a payload prefix, or a parallel state
machine.

## Durable-field audit

Already durable in the exact OPEN / NM3R record:

- transfer ID, origin transaction ID, origin event ID;
- source and target Runtime IDs;
- Service namespace, Service ID, schema ID, descriptor revision and digest;
- logical length, whole-content digest and deadline;
- receiver publication token, once the receiver reaches `READY`.

Required by the existing Application validation, callback, and Receipt path,
but missing from the durable OPEN:

- original Application attempt ID;
- source and target Application-instance IDs and complete identity bindings;
- Service family and exact schema major/minor;
- Application generation;
- required evidence and evidence grace;
- target ordinal.

The initial Foundation carrier contains part of the party/target binding only
while the process is live.  Its transaction/attempt/service are the private
MFDT control envelope, not the original Application envelope.  The current
volatile Runtime binding is therefore not a restart authority.

## Lean normative decision (SPEC_ACCEPTED)

### 1. Extend canonical TRANSFER_OPEN once

Keep the existing first 234 bytes, then append one fixed 228-byte canonical
Application binding before the three variable text IDs:

```text
offset  bytes  field
234     16     original_attempt_id
250      4     target_ordinal_u32
254     16     source_application_instance_id
270     16     source_device_id
286     16     source_installation_id
302     16     source_site_domain_id
318      8     source_binding_epoch_u64
326      8     source_membership_epoch_u64
334      4     source_identity_flags_u32
338      4     source_reserved_u32 = 0
342     16     target_application_instance_id
358     16     target_device_id
374     16     target_installation_id
390     16     target_site_domain_id
406      8     target_binding_epoch_u64
414      8     target_membership_epoch_u64
422      4     target_identity_flags_u32
426      4     target_reserved_u32 = 0
430      2     service_schema_major_u16
432      2     service_schema_minor_u16
434      4     service_family_u32
438      8     application_generation_u64
446      8     evidence_grace_ms_u64
454      4     required_evidence_u32
458      4     application_binding_flags_u32 = 0
462      N     namespace || service || schema
```

The revised OPEN maximum is 651 bytes and remains below the existing NCL1
body ceiling.  The manifest digest must bind the fixed Application binding as
well as the pre-existing OPEN header, text IDs, and manifest entries.

The fixed encoding is intentional.  Optional identity sub-layouts would save
little airtime on a one-time OPEN while adding parser and restart complexity.

### 2. Validate carrier and OPEN as one authority

Before receiver durable admission:

- source/target Runtime, Application instance and identity fields in OPEN
  must match the initial Foundation carrier exactly;
- Service, family, schema, generation, evidence and deadline fields must form
  one valid ordinary Application envelope;
- target ordinal must be within the Foundation exact-target bound;
- Runtime integration must rederive the expected transfer ID from origin
  transaction, target Runtime and target ordinal and require an exact match.

After restart, the exact OPEN in NM3S/NM3R is sufficient to rebuild the
carrier direction and the original Application delivery.  The volatile
binding remains a cache only and must not be required authority.

### 3. Add only durable Foundation correlation that cannot be derived

NTS3 must add:

- `mfdt_transfer_id[16]`, all zero for non-MFDT routes;
- `mfdt_target_ordinal_u32`, zero for non-MFDT routes and exact for MFDT.

The NTS3 schema minor must advance.  Do not add a duplicate durable
`delivery_context_id`.  The existing public callback token keeps the
Foundation transaction ID as its `context_id`, including for MFDT-backed
delivery.  The private Runtime bridge resolves the already-durable publication
token through the exact `mfdt_transfer_id` correlation and uses it only for
MFDT handoff/deduplication.  This avoids changing public deferred-callback
lookup semantics.

The private MFDT admission profile must also advance so old and revised OPEN
layouts cannot silently interoperate.  Old private rows/peers fail closed;
the feature remains default OFF and no public ABI changes in this repair.

### 4. Close multi-target admission without a new state machine

For MFDT V1 only, canonicalize the exact target roster and reject repeated
`target_runtime_id` values before any attempt entropy call.  A repeated Runtime
is unsupported even when its target Application-instance IDs differ.  Preserve
the existing public result: `NINLIL_OK` with submission
`REJECTED / TARGET_COUNT_UNSUPPORTED`; entropy, sidecar mutation, and Foundation
mutation are zero.  Do not introduce a compound receiver key.

Within the same owner-thread admission call, visit targets in canonical order.
For each target, select a non-zero attempt candidate using the existing maximum
four entropy draws and collision rules.  The collision set is the durable
active/retained attempt index plus candidates already selected earlier in this
same admission.  Put that candidate into the target's OPEN and FULL its
target-local sidecar arm.  Until every arm is durable and the later Foundation
admission FULL succeeds, none of these candidates is publicly or durably
projected as a consumed attempt; wire, TxGate acquisition, and callback remain
zero.

After all arms are `NEW`, one Foundation FULL atomically commits the exact
roster, each target's attempt index/binding, attempt budget/counters, existing
`ATTEMPT_PREPARED` / pending state, and its MFDT transfer ID/origin ordinal.
Candidate or arm definite failure performs no Foundation FULL and boundedly
cleans only arms already created.  Foundation definite failure cleans all arms.
Cleanup or arm `COMMIT_UNKNOWN` fences for cold reconciliation; Foundation
`COMMIT_UNKNOWN` retains all arms, fences, and reconciles.  An unresolved or
restarted admission never blindly redraws attempts.  Existing pre-Bearer-open
reconciliation is sufficient, so this repair adds no state, kind, or API.

Terminology is also explicit: public `ninlil_delivery_token_t` completes a
Foundation callback, while private `publication_token` identifies MFDT
handoff/deduplication.  The ADR diagram's `mfdt_publication_token` is only an
unambiguous label for the existing private field, not a third token or new API.

## Exact handoff ordering (SPEC_ACCEPTED)

1. Receiver commits verified content and publication `READY` to NM3R.
2. Runtime reconstructs the canonical Application envelope from OPEN and
   commits one inbound Foundation transaction with logical length, zero inline
   bytes, MFDT route, transfer ID and target ordinal.
3. Existing callback/reconcile machinery keeps its Foundation transaction ID
   delivery context and borrows the verified sidecar payload read-only.  The
   private bridge retains the publication token as the MFDT handoff key.
4. Application result and evidence become FULL in the Foundation transaction.
5. Runtime derives one canonical evidence digest from the publication token,
   origin transaction, attempt, target ordinal, evidence stage and evidence
   bytes.  The normative ADR must freeze the exact byte preimage.
6. Receiver commits that digest with `PUBLISHED/HANDOFF_COMPLETE` in NM3R.
7. Only then may the existing Application Receipt path send and durably track
   the Receipt reconstructed from the original Application binding.
8. Receipt closure precedes receiver MFDT terminalization and content release.

No callback may occur before step 2 FULL.  No Receipt may occur before steps 4
and 6 FULL.  `COMMIT_UNKNOWN` stops later mutation and wire output until cold
recovery classifies both stores.

Only a positive Application outcome whose durable evidence satisfies the
original `required_evidence` may advance steps 5 through 8.  Deferred delivery
continues through the existing Foundation reconcile path.  A disposition,
fatal callback result, or recovery fence must not claim MFDT handoff, Receipt,
or content release; the receiver retains custody until the existing recovery
or explicit authority action resolves the Foundation transaction.  This repair
does not add a second outcome state machine.

## Restart classification

| Durable state | Required action |
| --- | --- |
| MFDT READY, Foundation transaction absent | create the exact inbound transaction; callback not yet called |
| Foundation transaction present, no durable app evidence | resume existing callback/reconcile using the same Foundation transaction token; retain the publication token internally |
| Foundation app evidence FULL, MFDT still READY | do not call the app again; recompute evidence digest and resume handoff |
| MFDT handoff complete, Receipt open | do not call the app again; resume the existing Receipt path |
| Receipt closed, MFDT handoff complete | terminalize and release under the existing retention policy |
| any identity, digest, transfer, ordinal or state mismatch | fail closed as storage corruption; callback and Receipt zero |

## Implementation order

1. **Complete:** update ADR-0021, its machine vector/generators/gates,
   admission profile revision, exact OPEN/NM3S/NM3R sizes and storage budgets;
   obtain an independent spec review.
2. Implement the revised OPEN codec and carrier/OPEN equality validation with
   byte KATs and mutation tests.
3. Advance NTS3 and persist only transfer ID plus target ordinal.
4. Add the private READY-to-Foundation bridge by reusing the existing
   transaction, callback/reconcile, evidence and Receipt state machine.
5. Add restart fault injection at every boundary above, then Host 32 KiB E2E.
6. Keep ESP and physical HIL `NOT_RUN` until the same path builds and executes
   on target hardware.

## Minimum acceptance

- revised OPEN and active-record byte KATs, every added field mutation, and
  exact size/budget boundaries;
- initial carrier/OPEN mismatch rejected before durable mutation;
- 927, 4096 and 32768-byte Host Runtime apply with byte-exact payload;
- callback dedupe/reconcile keeps one stable Foundation transaction token,
  while MFDT handoff dedupe keeps one stable publication token;
- Receipt restores attempt, party/target, Service/family/schema, generation,
  evidence and target ordinal exactly;
- cold restart before/after Foundation transaction, callback evidence,
  MFDT handoff, Receipt send and terminalization;
- Foundation and MFDT `COMMIT_UNKNOWN` never permit later callback or wire;
- canonical 1..4-target MFDT admission binds one unique attempt/OPEN/sidecar arm
  per target before one Foundation FULL, including max-four collision and every
  definite/`COMMIT_UNKNOWN` cut;
- duplicate target Runtime (including different Application-instance IDs) is
  rejected with the existing unsupported-roster result before entropy or storage;
- ordinary single-frame and MFDT-OFF paths remain unchanged.

## Nonclaims

This SPEC_ACCEPTED repair does not complete Application apply, Receipt, ESP support, physical
transport, power-cut HIL, public module support, default-ON, or release support.
