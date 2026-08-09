# ADR-0038: Ninlil Runtime 1.0 integration program

- Status: **Proposed**
- Date: 2026-08-09
- Scope: V2 / Runtime 1.0 completion after the private V1 LAB
- Depends on: ADR-0032, ADR-0034
- Keeps: ADR-0034 V1 LAB scope and `HIL_VERIFIED` ceiling
- Normative candidate: [docs/37](../37-runtime-1.0-integration-program.md)

## Context

The repository has a public Runtime, Fabric and Composition, plus private
software candidates for Production Attachment, secure radio, relay,
multi-parent, Wi-Fi and multi-frame transfer. The three-board NJM1 LAB proves
that the board and a small automatic route loop can operate over real RF, but
it is unauthenticated and does not exercise those formal Runtime engines.

ADR-0034 intentionally defines V1 as a LAB-only single-hop SDK and moves these
production features to V2. This ADR does not reopen or supersede that decision.
Its target is the later Runtime 1.0 release.

## Decision

1. `ninlil_composition_v1_t` remains the single public Runtime/Fabric owner.
   No second Runtime, transport manager, public route API or plugin framework
   is introduced.
2. Work ownership remains exactly compatible with ADR-0032: Runtime owns MFDT
   through `budget.runtime`; `reliability_work` covers only route/parent and
   radio fragmentation; Fabric providers use `fabric_work`. Attachment is a
   separately bounded canonical management producer whose validated result is
   consumed by Composition. It is not charged to `reliability_work`.
3. NJM1 remains a private LAB profile. Its wire, unauthenticated site state,
   route table and Join state are not imported into formal Runtime code.
4. The existing `ninlil_identity_attachment_precondition_v1` contract is the
   sole Attachment activation handoff. A simplified activation DTO, copied
   raw secret or LAB binding is forbidden.
5. Before its consumer is implemented, the identity-precondition subset of
   ADR-0028 or a dedicated exact-contract ADR must reach `SPEC_ACCEPTED`, and
   the compatibility matrix must be updated from matching S1-S6 evidence.
   Domain Store ownership and its restart floor remain binding unless that
   authority, the manifest and the matrix are amended spec-first.
6. The dependency order follows existing authorities rather than a new status
   taxonomy: identity precondition acceptance; PA-S1-S4 direct Attachment;
   M5/M7 scheduler and secure RF/Wi-Fi/USB Fabric closure; PA-S5/S6 lifecycle
   and direct HIL; required NRW1 LINK/FRAG and U6 carrier closure; a new spec-first cold
   pre-Attachment forwarding tranche; M8 relay; M9 multi-parent; then M10/M11
   and the accepted C1-C10 completion contract. M1b/M2 and Runtime-owned MFDT
   progress in parallel lanes and join before M11.
7. A direct-Attachment tranche states that every joining node is in direct
   Controller range. It cannot claim NJM1-equivalent cold multi-hop Join.
8. Formal code may reuse public Composition/Fabric calls, bounded packet-link
   mechanics, the sole RF owner and measured turnaround timings. It must not
   include `v1_lab_*` binding types, raw LAB secrets or fixed pair/flow/service
   assumptions.
9. M1b and M2 are accepted only by closing every canonical roadmap item and
   exit gate. Reserved families remain unsupported under ADR-0024 until a
   dedicated Accepted unfreeze decision exists.
10. `RELEASE_SUPPORTED` remains the only full-completion state. The Proposed
    completion contract in docs/34 and each related ADR must first reach
    `SPEC_ACCEPTED`; no proposed document is implementation authority.

## Consequences

- V1 remains an honest LAB milestone while all later work advances the same
  Runtime toward 1.0.
- Existing implementation investment is reused without freezing private
  engine APIs as public SDK surface.
- Production trust cannot be fabricated by a Host fixture or copied LAB
  binding.
- Cold multi-hop Join is an explicit missing control-plane tranche rather than
  an accidental RRMP claim.

## Acceptance before status promotion

- The exact identity precondition subset is `SPEC_ACCEPTED` and its manifest
  and compatibility state agree.
- Direct Attachment and cold multi-hop Attachment are separately specified.
- Composition ownership and work budgets match ADR-0032 exactly.
- The program crosswalk retains every PA-S, M1b-M11 and applicable C1-C10 exit
  gate, including M8 100-node soak and M9 split-brain HIL.
- No formal source includes a `v1_lab_*` contract header.
- Independent review reports P0=0, P1=0 and P2=0 for this ADR and docs/37.

## Non-claims

This Proposed ADR does not implement or accept Production Attachment,
pre-Attachment forwarding, radio Fabric mapping, RRMP HIL, M1b/M2, legal
approval or a Runtime release.
