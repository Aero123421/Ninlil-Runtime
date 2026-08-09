# Production Attachment PA-S2b1 ephemeral P-256 candidate review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: private ephemeral P-256 and fixed-vendor opaque-token bridge candidate  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `26ae79f5b779a303db90e52ef2ca1a659a43b247`
- 10-file reviewed implementation/spec input manifest SHA-256 (sorted
  per-file SHA-256 lines; post-review README, work and review ledgers
  excluded):
  `d2dd25ed804905df9b678310d2ac7f15c762a294e0e245cbbacc1593c27a1c5c`
- ESP ELF SHA-256:
  `601dba687f64ead8d6e50e1ab04ae4f31c59fb764048b8c2ed59cbbd4a16e434`
- ESP BIN SHA-256:
  `8f22a3e995a625115a0a3f797697419d715f0b636b781f7530512ec91aed4d1b`

## Accepted candidate evidence

- the existing private PA-S2 owner and two fixed 64-byte slots are reused;
  no public crypto abstraction, owner, wire, store or Composition path was
  added;
- the adopted libedhoc method-3 flow sees only a separately drawn 32-byte
  opaque token while the P-256 scalar remains in the private backing slot;
- make handle, scalar/token backing and each agreement operation use distinct
  generation/state, with exactly two serialized uses and rejection of stale,
  repeated, simultaneous, wrong-token and third-use attempts;
- backing, first-operation and second-operation generations are reserved
  atomically before key-generation success, including the maximum-generation
  boundary and an unrelated-key interleave regression;
- independent Host KAT evidence covers both RFC 9529 method-3 roles, compact
  P-256 X validation, invalid field/non-curve inputs, entropy rejection and
  reentry, aliasing, output non-publication and immediate failure/end
  zeroization;
- the final normal, sanitizer, feature-OFF and focused gate suites pass; the
  candidate remains default-OFF, private, uninstalled and absent from the
  public Runtime archive;
- the explicit ESP-IDF v5.5.3 ESP32-S3 build enables the required mbedTLS
  primitives, links the same private source, exposes four owner symbols only
  as `GLOBAL HIDDEN`, and records 26 stack rows with a maximum frame of
  **336 B** under the 2048-byte ceiling.

The Ponytail review found no redundant public layer, parallel key owner,
wire, storage path or task. The change is a bounded extension of the existing
private PA-S2 callback owner.

## Status boundary

This GO accepts only the private PA-S2b1 ephemeral P-256/token candidate.
The ESP artifact was compiled and linked but not flashed or executed. ESP
target KAT, Host/ESP byte equality, a vendor-independent token ABI, provider
internal allocation ceilings, credential resolution, Factory Identity and
Site Membership authority, local static-DH, an all-exit EDHOC message owner,
real handshake, PA-S2 as a whole, PA-S3 through PA-S6, Composition, Join and
physical HIL remain open. ADR-0023 and the full Identity/Attachment feature
remain **Proposed**.
