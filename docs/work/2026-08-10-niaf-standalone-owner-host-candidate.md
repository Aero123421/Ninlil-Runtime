# NIAF standalone owner Host candidate

Date: 2026-08-10  
Status: **private Host candidate; ESP compile-only and Composition connection open**

## Change

`src/runtime/identity_attachment_v1/niaf_owner.[ch]` implements the accepted
NIAF S5 contract as a private, fixed-size standalone owner. It deep-copies the
1..255-byte caller locator before schema-1 open, uses the exact 72-byte key and
308-byte SHA-256/CRC-32C record, and uses
`ninlil_storage_canonical_apply()` as its sole write plan.

Recovery is a fresh zero-prefix READ_ONLY scan: zero rows is EMPTY; exactly one
exact key/value is CURRENT; every other result fences the owner. A FULL write
starts at generation 1, increments only for a semantic floor advance, and does
not write on a semantic no-op. Changing any identity/floor pair requires the
paired floor to increase strictly. `COMMIT_UNKNOWN` closes the old handle,
reopens the exact copied locator, scans again, and accepts only the prior or
proposed exact bytes.

The platform Storage close callback is `void`; no close-result is invented or
claimed. Every observable open/begin/iterator/capacity/write/rollback/reopen
failure fences the owner.

## Evidence

- `niaf_owner_v1`: key and record vector, EMPTY/CURRENT/restart/no-op/floor
  advance, wrong owner context, foreign/oversize/corrupt/second-record scan
  fencing, rollback and capacity faults, checkpoint regression/MAX fencing,
  identity/floor coupling, and `COMMIT_UNKNOWN` EMPTY/OLD/NEW/third/reopen-
  failure paths. A test-only Storage wrapper also proves callback-time owner
  reentry is rejected and malformed `iter_next` error outputs cannot expose
  partial data.
- Existing `identity_attachment_consumer_v1` remains a regression target.
- Fresh ESP-IDF v5.5.3 `smoke_app` compile/link completed without flash; the
  NIAF-only target `.su` gate reports a largest frame of 336 bytes. The final
  `build-niaf-owner-final3/ninlil_m3_combined_smoke.elf` SHA-256 is
  `b0c65bea8220b341892938ef7178899e37548c9ac90c66e87687969e4c88ce93`.

## Non-claims / next step

This adds no installed API, wire format, public DTO, Composition injection,
Production Attachment provider, Domain schema-1 catalog record, availability
publication, or HIL evidence. Next is private Composition injection only after
the owner’s Host/target acceptance is complete.
