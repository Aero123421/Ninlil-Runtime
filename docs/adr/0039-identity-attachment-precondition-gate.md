# ADR-0039: Identity / Attachment precondition gate

- Status: **Accepted**
- Date: 2026-08-10
- Scope: Runtime 1.0 consumer-start precondition only
- Extracts/accepts only: ADR-0028 section 1.1 exact contract, including its existing NIAF durability boundary
- Related: ADR-0022, ADR-0023, ADR-0032, ADR-0038
- Authority: `public-module-manifest.json#/identity_attachment_precondition_contract`
- Keeps: `identity-attachment-session-install` at `PROPOSED`; all existing public ABI, wire, and storage schemas
- Pre-amendment review: `docs/reviews/2026-08-10-identity-attachment-precondition-spec-review.md` (does not cover the NIAF namespace/recovery amendment)
- NIAF S5 amendment review: `docs/reviews/2026-08-10-identity-attachment-precondition-niaf-s5-amendment-review.md` (S1--S6 specification-only GO)

## Context

Runtime 1.0 modules need one authenticated, continuously-valid attachment
handoff before they make a network path available.  A shortened activation
record, a LAB pair binding, a QR-derived boolean, or copied secrets would omit
the lifecycle rules that make the handoff safe across invalidation and restart.

ADR-0028 section 1.1 already defines the exact contract as a machine-readable,
fail-closed authority.  Production Attachment itself remains the larger
Proposed profile in ADR-0023 and chapter 35. This ADR creates neither a
second contract nor a shortcut around its open evidence. The NIAF amendment
does not create a durable schema; it makes the existing checkpoint placement
and recovery rules exact.

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
5. Restart uses the `NIAF` schema-1, 308-byte FULL checkpoint and its
   Core/Foundation Domain Store standalone single writer. Only the non-secret
   floors named by the manifest persist. A fresh resolve and validation are required before
   availability; provider context, opaque handles, private scalars, and raw
   session keys are never persisted or exported.
6. NIAF is under the existing Core/Foundation Domain Store durability
   authority, while its dedicated storage namespace is outside the canonical
   Domain schema-1 catalog. Its locator is the caller-authoritative exact byte
   string: there is no default namespace, automatic prefix, Domain catalog
   cohabitation, or LAB-profile reuse. The Domain Store NIAF standalone owner
   alone opens and closes that exact locator with schema 1 and holds the
   owner-context, exclusive single-writer lease until close. This defines no
   public locator DTO or API and creates neither a Domain catalog row nor a
   Domain schema-1 dependency.
7. The exact binary storage key is 72 bytes:
   `4e4941462d4b3100 || realm_id16 || runtime_instance_id16 ||
   runtime_generation_le64 || module_instance_id16 ||
   module_generation_le64`. This is the manifest's existing canonical-key
   identity in byte form. No trailing byte is accepted. One key identifies
   one current checkpoint; the record's provider and all monotonic floors are
   value fields, not alternate keys.
8. Recovery classifies the exact locator and exact key as empty, exactly one
   current record, or failure. Unknown, multiple, corrupt, mismatched-key, or
   otherwise existing state fences availability and key use. Each update is
   one FULL atomic replacement. On `COMMIT_UNKNOWN`, an authoritative read of
   that exact locator/key accepts only exact EMPTY/last-proven OLD or the exact
   proposed NEW bytes, generation, and digest; a third value fences.
9. Composition cannot receive this caller-authoritative locator without a new
   public input, which this ADR forbids. The next implementation unit is a
   private standalone NIAF owner. Private Composition injection follows only
   after that owner and a private Production Attachment provider exist; this
   does not authorize a temporary Composition default or an availability
   publish.
10. The later consumer implementation acceptance remains
   `PM-IDENTITY-PRECONDITION-2X2-01`: two Runtime/module/provider bindings,
   cross/stale/rollback/revocation/expiry/restart negatives, subscribe and
   drain ordering, and zero key export.  Its implementation test remains
   `NOT_RUN` until a consumer seam exists.  The current spec gate and mutation
   self-test prove only that the exact contract cannot be silently weakened.
11. After `COMMIT_UNKNOWN`, the transaction is invalid: the owner closes its
    handle, reopens the same exact locator with schema 1, and performs a fresh
    READ_ONLY zero-prefix full scan. It never reads through the prior handle.
    On every startup or reopen, EMPTY means total scan count zero only;
    CURRENT means total count one with the exact 72-byte key and one valid
    exact 308-byte value whose key identities match. A second/other/unknown/
    oversize entry, iterator error, or any invalid value fences availability
    and key use; exact-get is insufficient to establish EMPTY.
12. The locator is opaque exact bytes of length 1 through 255, with non-NULL
    data. The owner deep-copies it before open and rejects invalid shape before
    open; normalization is forbidden. A fresh first FULL checkpoint has
    generation 1. Each accepted floor advance writes checked `+1`; a no-op
    writes nothing and does not advance. `UINT64_MAX`, rollback, wrap, or
    non-monotonic generation fences availability and key use; every new floor
    must be at least its old floor.

## Pre-amendment evidence and amendment boundary

The prior review is retained as historical evidence for the original contract
extraction. The dedicated amendment review covers decisions 6--12, fixes the
current contract digest, and records the fresh S1--S6 GO. This ADR does not
accept a consumer implementation, 2x2 execution, or physical HIL.

| Spec item | Current evidence |
| --- | --- |
| S1 | Manifest is the sole authority and the `fabric_v1` plus six consumer module roster is exact. |
| S2 | Existing provider ABI is specified without a new public header, wire, DTO, or secret export. |
| S3 | `resolve -> validate -> subscribe -> publish`, revalidation, invalidation, and drain ordering are exact. |
| S4 | `tools/identity_attachment_precondition_spec_gate.py` passes one exact 308-byte NIAF SHA-256/CRC-32C record and the LP64 plus ESP32-S3 Xtensa ILP32 provider-ABI layout vectors. |
| S5 | Dedicated amendment review confirms standalone owner boundary, locator/key, full-scan recovery, and generation contract. |
| S6 | Dedicated amendment review records GO with no unresolved P0/P1/P2/P3 finding. |

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

No PA-S item is complete merely because this ADR exists. The standalone NIAF
owner and later private Composition injection are implementation work, not
completion evidence.

## Promotion condition

The fresh independent review artifact, immutable digest, and passing spec KAT
cover S5/S6, so this amendment is `Accepted` and NIAF is `SPEC_ACCEPTED`.
The PA-S1--PA-S6 implementation evidence, consumer 2x2, Host execution,
ESP32-S3 target execution, and HIL remain later C5--C8 work. This amendment
leaves `identity-attachment-session-install` **PROPOSED** throughout.

## Non-claims

This ADR does not accept or implement the standalone NIAF owner, Production
Attachment, EDHOC, direct or cold multi-hop Join, a Composition consumer seam,
RF/Wi-Fi/USB transport, RRMP, multi-parent, Domain catalog changes, physical
HIL, legal compliance, or a Runtime 1.0 release.
