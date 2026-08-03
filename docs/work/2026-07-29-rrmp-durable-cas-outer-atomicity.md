# RRMP durable CAS / outer atomicity close

Date: 2026-07-29
Scope: private/default-OFF Route Relay + Multi-parent implementation

## Outcome

- Standard Storage bind now compares the exact current
  `(present, length, SHA-256)` tuple in the same READ_WRITE snapshot before
  replacing `RRMP/NS1`; a stale owner cannot blind-overwrite.
- A private storage-authority seam supplies durable exact CAS and cold
  `COMMIT_UNKNOWN` recovery for deployments with multiple handles/controllers.
  It is not installed and changes no public Storage ABI or wire record.
- Platform FULL is the outer writepoint. Definite begin/get/put/commit failure
  reloads exact OLD bytes and rebuilds RAM/inner dual pages. An unexpected
  third image is fenced as corrupt.
- Unresolved outer `COMMIT_UNKNOWN` fences mutation, route/parent selection,
  bearer send, workers, and state readback. Only exact OLD/NEW recovery clears
  the storage fence; semantic lease/split-brain/parent-loss fences survive.
- S6 no longer adds a redundant second outer NPS1 commit after its atomic
  NPA1/NPT1 + soft-state snapshot.

## Acceptance evidence

`ninlil_rrmp_storage_atomicity_test` independently covers:

- begin/get/put/commit definite failure with byte-for-byte durable OLD and
  exported RAM OLD restoration;
- standard-bind stale snapshot rejection;
- two owners restored from one pre-S3 snapshot with exactly one NPH1 authority
  commit and unique cold-restart truth;
- outer `COMMIT_UNKNOWN` exact OLD and exact NEW, including cold restart;
- PARTIAL and THIRD rejection;
- the global mutation/select/send/worker/read fence.

The existing crash/corrupt test was tightened so unresolved outer state cannot
expose post-mutation RAM through query.

Normative vector and private API catalog bytes/op lists are unchanged because
no status, request/result layout, wire record, public operation, or installed
ABI changed. Their generator/gate remains the consistency authority.

## Validation

- Host normal focused tests: PASS
- Host ASan focused tests: PASS
- Host UBSan focused tests: PASS
- Normative vector generator freshness/self-test and independent gate/self-test:
  PASS (114/114 required cases)
- Physical ESP32-S3/SX1262 HIL: **NOT_RUN**
