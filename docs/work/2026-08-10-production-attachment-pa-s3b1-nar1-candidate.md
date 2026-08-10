# PA-S3b1 private NAR1 admitted-reassembly candidate

Date: 2026-08-10  
Status: **independently reviewed Host/ESP compile candidate; PA-S3 remains open**

This spec-first tranche implements only the strict NAR1 codec and one admitted
single-record reassembly owner defined by the Proposed Production Attachment
profile. It does not promote ADR-0023 or complete PA-S3.

## Scope

The default-OFF, uninstalled private owner is caller-owned and serialized by an
exact owner context. It stores one 600-byte NAC1 buffer, one 5-bit received
mask, and the bound source/session/generation/sequence/length/digest/count
tuple. A full raw NAR1 packet is parsed and CRC-checked before owner mutation;
its canonical payload is copied directly to `index * 124`. Packet slots, heap,
VLA, task, pump, wire additions, public headers/API/DTO, and storage are absent.

Same duplicates make no progress. Malformed, mixed, source-mismatched, and
conflicting packets terminally wipe the partial record. Completion publishes
exactly once only after SHA-256 and the contained NAC1 structural and tuple
checks pass; caller output bytes after the exact record remain unchanged.

## Current evidence

- Strict Host build passes the focused 8/8 CTest set plus 10/10 vector,
  Python/Node, registry, and vendor gate checks, including the owner and
  installed-public-symbol boundary tests.
- The focused ASan/UBSan regression suite passes 3/3.
- Sol xhigh completed a read-only final review with
  **GO — P0=0 / P1=0 / P2=0 / P3=0** for this private candidate only.
- Tests exercise 1 through 5 fragments, exact final 124-byte boundaries, all
  120 five-fragment orders, exact duplicate/no-progress with full owner/output
  immutability, conflicting duplicate, canonical NAR1 shape, CRC, source and
  every independently mutable tuple field, all NAC1 structural fields, digest,
  owner/output/input alias rejection, lifecycle failures, wrong context,
  reentry, corrupted counters, output tail preservation, close zeroization,
  and two isolated owners. The new NAC1 table rejects deletion-equivalent
  mutants for 12 structural predicates; the existing carrier and CRC negatives
  remain separate. For NAR1, 8 newly added cases plus the existing version,
  offset, CRC, and exact-payload cases reject all 12 externally observable
  semantic parser-predicate deletion mutants. The short-span lower guard is
  separately deletion-checked under ASan with a one-byte input. Completion
  digest and inner tuple guards, and the OPEN full-mask shape guard, are also
  mutation-checked. The NAR1
  complete-length lower bound remains an explicit parse-before-mutation
  code-review invariant: its deletion is not externally distinguishable because
  same-call NAC1 completion validation also rejects it, so no mutation-test claim
  is made for that internal ordering.
- Redundant standalone NAC1 kind and NAR1 fragment-count range comparisons are
  absent: `sequence_ok` and exact `count = ceil(length / 124)` are their single
  executable authorities.
- Default-OFF/tests-OFF exposes no PA-S3b1 target or installed Runtime symbol.
- Host source-only stack evidence reports a 240-byte maximum frame under the
  2048-byte ceiling.
- ESP-IDF v5.5.3 image
  `espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb`
  compiles and links the same source under explicit Kconfig opt-in. The three
  owner functions are `GLOBAL HIDDEN` in the final ELF. Source-only Xtensa
  stack evidence reports a 176-byte maximum frame under the 2048-byte ceiling.
- Fresh compile/link-only artifacts (not flashed or executed):
  `build-pa-s3-nar1-optin-final2/ninlil_m3_combined_smoke.elf`, SHA-256
  `98f3f063a76a215657f21db52a91076157615f2015d785563236c445fb68223c`;
  517,312-byte `.bin`, SHA-256
  `b0b3adc187e6112c7a3655788dedbef193a30810bbf99505db6e4aed31fd1a6c`.

## Open evidence

The caller-supplied source digest is Host-test identity only. Live source
locator ownership, cookie secret/bucket/HMAC, challenge, carrier admission,
anti-amplification quota, timeout/retry scheduling, RF ingress/TX, EDHOC
message owner, NAC1 live handoff, Composition, NIAF, availability, Join,
ESP target execution, and physical HIL remain open.
PA-S3 through PA-S6 and ADR-0023 remain Proposed/open.
