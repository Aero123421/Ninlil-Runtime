# ADR-0039: Identity / Attachment precondition gate

- Status: **Accepted**
- Date: 2026-08-10
- Scope: Runtime 1.0 consumer-start precondition only
- Extracts/accepts only: ADR-0028 section 1.1 exact contract
- Related: ADR-0022, ADR-0023, ADR-0032, ADR-0038
- Authority: `public-module-manifest.json#/identity_attachment_precondition_contract`
- Keeps: `identity-attachment-session-install` at `PROPOSED`; all existing public ABI, wire, and storage schemas
- Acceptance review: `docs/reviews/2026-08-10-identity-attachment-precondition-spec-review.md` (S1--S6 specification-only GO)

## Context

Runtime 1.0 modules need one authenticated, continuously-valid attachment
handoff before they make a network path available.  A shortened activation
record, a LAB pair binding, a QR-derived boolean, or copied secrets would omit
the lifecycle rules that make the handoff safe across invalidation and restart.

ADR-0028 section 1.1 already defines the exact contract as a machine-readable,
fail-closed authority.  Production Attachment itself remains the larger
Proposed profile in ADR-0023 and chapter 35.  This ADR creates neither a
second contract nor a shortcut around its open evidence.

## Decision

1. The sole contract authority is
   `public-module-manifest.json#/identity_attachment_precondition_contract`,
   whose canonical bytes, schema copy, and mutation checks are pinned by
   `tools/public_module_manifest_gate.py`.  This ADR deliberately does not
   restate a DTO, C layout, field order, wire record, or key material.
2. The contract remains a Core/Foundation precondition, not an installable
   package component.  This is not a new ABI allocation: it accepts the
   already-manifested provider ABI as specification only, with no new public
   header, callback ABI, wire magic, storage schema, activation DTO, or
   secret-export path introduced here.
3. `compatibility-matrix.json` keeps
   `identity-attachment-session-install` at `PROPOSED`.  A separate completion
   feature is not created: it would make a contract-only planning artifact look
   like an independently usable Attachment implementation.  The manifest's
   existing versioned precondition dependencies remain the consumer fence.
4. A consumer can publish availability only in this exact order:
   `resolve -> validate -> subscribe -> publish`.  It revalidates before
   admission and before send.  An invalidation fences new and inflight use
   before the callback returns; shutdown drains key operations and callbacks
   before binding release.  These are manifest rules, not a new runtime loop.
5. Restart uses the existing `NIAF` schema-1, 308-byte FULL checkpoint and the
   Core/Foundation Domain Store single writer.  Only the non-secret floors
   named by the manifest persist.  A fresh resolve and validation are required
   before availability; provider context, opaque handles, private scalars, and
   raw session keys are never persisted or exported.
6. The later consumer implementation acceptance remains
   `PM-IDENTITY-PRECONDITION-2X2-01`: two Runtime/module/provider bindings,
   cross/stale/rollback/revocation/expiry/restart negatives, subscribe and
   drain ordering, and zero key export.  Its implementation test remains
   `NOT_RUN` until a consumer seam exists.  The current spec gate and mutation
   self-test prove only that the exact contract cannot be silently weakened.

## S1 to S6 specification acceptance

This ADR is **Accepted** as a specification extraction because every item
below has independent review evidence and the spec KAT passes. It does not
accept a consumer implementation, 2x2 execution, or physical HIL.

| Spec item | Exact evidence for this Accepted decision |
| --- | --- |
| S1 | Manifest is the sole authority and the `fabric_v1` plus six consumer module roster is exact. |
| S2 | Existing provider ABI is specified without a new public header, wire, DTO, or secret export. |
| S3 | `resolve -> validate -> subscribe -> publish`, revalidation, invalidation, and drain ordering are exact. |
| S4 | `tools/identity_attachment_precondition_spec_gate.py` passes one exact 308-byte NIAF SHA-256/CRC-32C record and the LP64 plus ESP32-S3 Xtensa ILP32 provider-ABI layout vectors. |
| S5 | NIAF single-writer restart floors, fresh-resolution fence, and secret exclusions are exact. |
| S6 | The independent review checks all S1--S5 claims and records no unresolved P0/P1/P2/P3 finding. |

`ESP32S3_XTENSA_ILP32` in S4 is a numeric specification profile: ESP-IDF
v5.5.3 / `xtensa-esp32s3-elf-gcc` reports data and function pointers as
4-byte/4-aligned and `uint64_t` as 8-aligned.  It is not a substitute for the
later target compile and executed-test evidence.

## Later PA-S1 to PA-S6 / C5 to C8 boundary

This is a specification gate, not closure of Production Attachment evidence.

| Chapter 35 tranche | This ADR fixes | Still open |
| --- | --- | --- |
| PA-S1 / C5 | provider/allocator ownership boundary | dependency and allocator acceptance |
| PA-S2 / C5-C6 | non-exporting key-operation contract | crypto provider KAT and interoperability |
| PA-S3 / C5-C6 | validated-result-only consumer boundary | NAS1/NAR1 and EDHOC owner |
| PA-S4 / C5-C6 | publish-after-durable truth rule | protected exchange and 15-key install owner |
| PA-S5 / C6-C7 | invalidation and restart-floor contract | lifecycle/fault implementation evidence |
| PA-S6 / C7-C8 | 2x2 acceptance shape | USB/Wi-Fi/SX1262 HIL and final review |

No PA-S item is complete merely because this ADR exists.

## Acceptance before promotion

This ADR is `Accepted` because the S1--S6 specification table is satisfied:
an independent review artifact reports `GO` with no unresolved P0/P1/P2/P3
finding, and the independent spec KAT passes. The PA-S1--PA-S6
implementation evidence, consumer 2x2, Host execution, ESP32-S3 target
execution, and HIL remain later C5--C8 work.  Consequently, accepting this
ADR leaves `identity-attachment-session-install` **PROPOSED** in the
compatibility matrix until its existing completion evidence is actually done.

## Non-claims

This ADR does not accept or implement Production Attachment, EDHOC, direct or
cold multi-hop Join, a Composition consumer seam, RF/Wi-Fi/USB transport,
RRMP, multi-parent, Domain Store repair, physical HIL, legal compliance, or a
Runtime 1.0 release.
