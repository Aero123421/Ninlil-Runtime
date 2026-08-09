# Production Attachment PA-S3a NAS1 direct-stream candidate review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: private NAS1 incremental receive owner and NAC1 structural validator  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `7d8fe83bc3acfdb614f35a4ff966273a4df27fe1`
- 12-file reviewed implementation/spec input manifest SHA-256 (sorted
  per-file SHA-256 lines; post-review README, work and review ledgers
  excluded):
  `321205c531a160ef555a55959a030f380f0d87a47cb76901943d4aa3c04ec1a3`
- ESP ELF SHA-256:
  `3913f2a2a10f0c0bc6f8525c59453c71cef1b445db223a8c2320a0b739ae0abd`
- ESP BIN SHA-256:
  `f68c5c11b3aa1a12e2195d24db875b852fb4f238144e622fba374f027fc04c74`

## Accepted candidate evidence

- one private owner holds one fixed 612-byte NAS1 wrapper and accepts only
  serialized `feed`, EOF and close calls from its exact owner context;
- no partial, malformed, overflow, trailing, short-EOF, future-version or
  expected-tuple mismatch path publishes caller output; exact completion
  copies one NAC1 record once and close zeroizes the complete owner;
- the same translation unit validates exact NAC1 length, CRC, kind/sequence,
  reserved fields, carrier, session, exchange generation and binding without
  introducing a general codec or claiming an Attachment authority;
- Host evidence covers the valid 88-byte and 600-byte NAC1 boundaries, every
  kind/sequence class, single and `1/6/5/79/rest` reads, all prefixes,
  coherent tuple mismatches, capacity/counter corruption, pointer aliasing,
  reentry and two-owner isolation;
- eight independent deletion mutants for outer/inner carrier, kind, sequence,
  capacity, buffered/wrapper counters and input-owner alias all fail;
- focused Host evidence passes **16/16**, ASan/UBSan passes **1/1**, and the
  feature-OFF build exposes neither a target nor a public Runtime symbol;
- the explicit ESP-IDF v5.5.3 ESP32-S3 build links the same source, exposes
  only the three owner functions as `GLOBAL HIDDEN`, and records a maximum
  source frame of **64 B** under the 2048-byte ceiling.

The Ponytail review found no generic stream framework, public ABI, task,
storage path, parallel authority owner or new wire format. NAC1 validation is
kept as private static code beside the only consumer.

## Status boundary

This GO accepts only the private PA-S3a NAS1 direct-stream candidate. The ESP
artifact was compiled and linked but not flashed or executed. Real socket
reads, accepted-carrier admission, Factory Identity and Site Membership
authority, credential resolution, local static-DH, an all-exit EDHOC message
owner, NAR1/radio, Composition/NIAF activation, availability, real handshake,
PA-S2/PA-S3 as a whole, PA-S4 through PA-S6, Join and physical HIL remain
open. ADR-0023 and the full Identity/Attachment feature remain **Proposed**.
