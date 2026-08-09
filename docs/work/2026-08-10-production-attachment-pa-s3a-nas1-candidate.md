# PA-S3a private NAS1 direct-stream candidate

Date: 2026-08-10  
Status: **independent final GO / Host candidate / ESP32-S3 compile-link-stack only; PA-S3 remains open**

This spec-first tranche implements only the direct USB/Wi-Fi stream framing
boundary already defined by the Proposed Production Attachment profile. It
does not promote ADR-0023 or complete PA-S3.

## Scope

The default-OFF, uninstalled private owner holds one fixed 612-byte NAS1
receive buffer and accepts serialized `feed`, EOF, and close calls from one
exact owner context. A complete wrapper is copied to the caller exactly once
only after both NAS1 and the contained NAC1 match the expected carrier,
session, exchange generation, kind, sequence, binding digest, lengths, and
CRC. Partial input publishes no bytes. Short EOF, trailing/overflow bytes,
malformed input, future versions, and tuple mismatch close without delivery;
close zeroizes the complete owner.

The implementation adds no public header/API/DTO, installed target, storage
record, wire format, general stream abstraction, task, pump, or LAB dependency.
It does not connect sockets, accepted-carrier admission, Factory Identity,
Site Membership, credentials, static DH, an EDHOC message owner, NAR1/radio,
Composition, NIAF, availability, or Join.

## Evidence

- The Host fixture is generated from the existing Production Attachment
  oracle. Tests cover the exact 88/600-byte NAC1 bounds, every valid
  kind/sequence pair, single-read and every-prefix partial delivery,
  `1/6/5/79/rest`, short EOF, trailing and overflow bytes, NAS1 and NAC1 field
  mutations, CRC, invalid kind/sequence pairs, carrier/session/generation/
  binding mismatches, copied-length/tail preservation, wrong context, owner
  reentry, close zeroize, output/input/owner alias rejection, and two-owner
  isolation. Four structurally valid tuple-mismatch tests independently make
  outer carrier, inner carrier, expected kind, and expected sequence comparison
  deletion mutants fail. Capacity off-by-one and each corrupted internal length
  guard mutant, plus the input-versus-owner span guard deletion mutant, also
  fail before output or owner mutation can be accepted.
- Focused strict Host tests pass 16/16, including the C11 fixture, Python/Node
  oracles and mutation self-tests, magic registry, private-symbol boundary,
  and markdown links. ASan/UBSan passes the PA-S3a owner test 1/1.
- Default-OFF/tests-OFF has no PA-S3a target. Explicit opt-in with tests OFF
  builds only the private archive; the installed `ninlil_runtime` archive has
  no `ninlil_pa_s3_nas1_` symbol.
- ESP-IDF v5.5.3 image
  `docker.io/espressif/idf@sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1`
  builds the same source for ESP32-S3. The three owner functions are `GLOBAL
  HIDDEN` in the final ELF. Source-only stack evidence has eight rows and a
  64-byte maximum frame under the 2048-byte ceiling.
- Fresh compile/link-only artifacts (not flashed or executed):
  `build-pa-s3-nas1-optin-final/ninlil_m3_combined_smoke.elf`, SHA-256
  `3913f2a2a10f0c0bc6f8525c59453c71cef1b445db223a8c2320a0b739ae0abd`;
  516,592-byte `.bin`, SHA-256
  `f68c5c11b3aa1a12e2195d24db875b852fb4f238144e622fba374f027fc04c74`.

## Open evidence

Independent final review, ESP target execution, real socket reads, accepted
carrier admission, credential and static-DH authorities, EDHOC message
lifecycle, NAR1, Composition/NIAF activation, availability, Join, and physical
HIL remain open. PA-S2, PA-S3, PA-S4 through PA-S6, and ADR-0023 remain
Proposed/open.

## Final review

The frozen candidate received an independent Codex GPT-5.6 Sol xhigh
read-only review: **GO — P0=0 / P1=0 / P2=0 / P3=0**. Eight coherent deletion
mutants independently confirmed the outer/inner carrier, kind, sequence,
capacity, buffered/wrapper counter, and input-owner alias checks. The review
also closed the private/default-OFF packaging, final ESP artifact and stack
evidence, non-claim boundary, and Ponytail minimality. See
[the review record](../reviews/2026-08-10-production-attachment-pa-s3a-review.md).
