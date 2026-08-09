# Identity / Attachment precondition SPEC_ACCEPTED checkpoint

Date: 2026-08-10  
Status: **SPEC_ACCEPTED contract only — implementation and HIL open**

## Decision

ADR-0039 accepts the exact Identity / Attachment precondition extracted from
ADR-0028 section 1.1. The authority is the existing manifest contract
`ninlil_identity_attachment_precondition_v1`; no new public DTO, wire format,
secret export, or application vocabulary is introduced.

The NIAF schema-1 checkpoint is now `SPEC_ACCEPTED` as a specification
artifact. The corresponding compatibility feature
`identity-attachment-session-install` remains `PROPOSED`.

## Evidence

- Independent S1--S6 review: P0=0 / P1=0 / P2=0 / P3=0 GO.
- Independent NIAF 308-byte SHA-256 / CRC-32C and provider ABI KAT.
- LP64 and ESP32-S3 Xtensa ILP32 layout checks, including the pinned compiler
  static assertions for the target profile.
- Manifest, compatibility, protocol-magic, and identity gates plus mutation
  self-tests pass.

## Next step

Implement a private Composition consumer seam that follows
`resolve -> validate -> subscribe -> publish`, revalidates before admission
and send, and drains invalidation before release. Its Host acceptance comes
before any public promotion.

## Open work

PA-S1--PA-S6, `PM-IDENTITY-PRECONDITION-2X2-01`, direct/cold multi-hop Join,
ESP target execution, physical HIL, legal compliance, and release remain open.
