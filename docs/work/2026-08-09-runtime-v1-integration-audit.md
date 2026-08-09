# Runtime 1.0 integration audit — 2026-08-09

Status: **PLAN REVIEW GO / IMPLEMENTATION NOT STARTED**

## User goal correction

The target is not a polished private mesh LAB. The target is a formal Ninlil
Runtime whose public Runtime/Composition can use Attachment, LoRa, Wi-Fi,
relay, multi-parent, multi-frame data and a Controller without application-
specific vocabulary.

## Audit result

- Public Runtime/Fabric/Composition and multi-Service registration exist.
- LatestState, Measurement and subscription remain reserved/unsupported.
- Production Attachment is Proposed and PA-S1..S6 are open.
- RRMP, MFDT and Wi-Fi are private/default-OFF candidates.
- NJM1 auto Join/topology is private, unauthenticated LAB evidence only.
- `composition_v1.c` currently reports zero reliability work because internal
  engines are not connected.

## Rejected shortcuts

1. A new simplified Activation claim would duplicate
   `ninlil_identity_attachment_precondition_v1` and omit continuous
   validation/invalidation/key-handle/restart-floor rules.
2. Formal RRMP activation and physical acceptance cannot precede an active
   Production Attachment. Existing private implementation and isolated Host
   tests may remain experimental.
3. NAR1 is direct one-hop and RRMP is post-Attachment, so cold multi-hop Join
   needs a separate pre-Attachment forwarding contract.
4. `v1_lab_*` raw secret/binding/fixed-pair types are not formal Runtime types.
5. Network completion does not silently complete the M1b/M2 Application API.

## Draft authority

- [docs/37](../37-runtime-1.0-integration-program.md)
- [ADR-0038](../adr/0038-runtime-1.0-integration-program.md)

The draft was created after a Terra high implementation-path audit and a Sol
xhigh independent review. The review of the pre-draft plan was NO-GO with
P0=0/P1=3/P2=3. The first actual-draft review was also NO-GO
(P0=0/P1=4/P2=2/P3=2): it found a conflict with ADR-0034, incorrect ADR-0032
budget ownership, a missing identity SPEC_ACCEPTED gate and a duplicate
I0-I8 taxonomy. The revised docs/37 and ADR-0038 keep V1 LAB unchanged and map
work directly to PA-S/M/C authorities. A fresh review then removed an
unnecessary MFDT-to-relay dependency and finished with
**GO, P0=0 / P1=0 / P2=0 / P3=0**. The review artifact is
[here](../reviews/2026-08-09-runtime-1.0-integration-program-review.md).

ADR-0038 remains Proposed. The next implementation gate is the exact
identity-precondition contract reaching `SPEC_ACCEPTED`; review GO by itself
does not authorize Attachment or RF production claims.
