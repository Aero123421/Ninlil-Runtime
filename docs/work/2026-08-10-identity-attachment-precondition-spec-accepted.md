# Identity / Attachment precondition SPEC_ACCEPTED checkpoint

Date: 2026-08-10  
Status: **SPEC_ACCEPTED contract and NIAF S5 amendment; implementation and HIL open**

## Decision

ADR-0039 accepts the exact Identity / Attachment precondition extracted from
ADR-0028 section 1.1. The authority is the existing manifest contract
`ninlil_identity_attachment_precondition_v1`; no new public DTO, wire format,
secret export, or application vocabulary is introduced.

The original NIAF schema-1 checkpoint extraction was `SPEC_ACCEPTED` as a
specification artifact. Its caller-authoritative dedicated namespace/key under
the Core/Foundation Domain Store durability authority (but outside the
canonical Domain schema-1 catalog) is a later S5 amendment and is
`SPEC_ACCEPTED` after its own fresh independent review; it does not inherit
the older review.
The corresponding compatibility feature
`identity-attachment-session-install` remains `PROPOSED`.

## Evidence

- Historical independent S1--S6 review: P0=0 / P1=0 / P2=0 / P3=0 GO;
  it predates and does not cover the NIAF S5 amendment.
- NIAF S5 amendment independent review: P0=0 / P1=0 / P2=0 / P3=0 GO.
- NIAF S5 amendment review artifact SHA-256: `6d2e59b70a0b998bbf1d25f6de3dc4fb35beb27aa1ce3fa6b3fdc0c3834a12e6`.
- Independent NIAF 308-byte SHA-256 / CRC-32C and provider ABI KAT.
- LP64 and ESP32-S3 Xtensa ILP32 layout checks, including the pinned compiler
  static assertions for the target profile.
- Manifest, compatibility, protocol-magic, and identity gates plus mutation
  self-tests pass.

## Next step

Implement a private standalone NIAF owner first. It must recover the exact
locator/key, classify FULL/`COMMIT_UNKNOWN` truth, and persist floors without
publishing availability. Only then can a private Composition injection seam
be designed; the public Composition API has no locator input and is unchanged.

## Open work

The standalone owner, Composition injection, PA-S1--PA-S6,
`PM-IDENTITY-PRECONDITION-2X2-01`, direct/cold multi-hop Join, ESP target
execution, physical HIL, legal compliance, and release remain open.
