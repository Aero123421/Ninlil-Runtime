# RRMP P1 repair contract — 2026-07-29

Status: **PROPOSED REPAIR CONTRACT / NO-GO until implemented and independently
re-reviewed**

This work record turns the six independent-review P1 findings into one
coherent repair order. It is not itself Normative. ADR-0019, ADR-0020, the
machine vectors and the private API catalog must be amended first; production
code may then follow those amended authorities.

## Non-negotiable constraints

- The public Platform Storage single-value ceiling remains exactly 65,536
  bytes. RRMP must never issue a larger `put`.
- The canonical inner route and parent domains remain 21 and 22 physical keys
  respectively. The obsolete 17-key value is forbidden.
- A green test using a 256 KiB mock value is not evidence of compatibility
  with Platform Storage.
- Parent-set installation is not an authority transition and cannot clear an
  attempt, parent-loss or split-brain fence.
- No same-attempt reselection is allowed, including A→B→A, restart, assignment
  revision change or handoff.
- Authority-writer split brain is authority-global. A parent anomaly that is
  demonstrably local to one scope remains scope-local; these are distinct
  events and APIs.
- Physical ESP flash/power-cut and RF HIL remain `NOT_RUN` until real artifacts
  exist.

## RRP-1 — bounded atomic Platform Storage bundle

The existing logical `RRMPNS1` export is retained as the canonical whole-state
preimage, but it is not a Platform Storage value. It is stored as a bounded
bundle in one caller-opened RRMP authority namespace so one Platform Storage
`FULL` transaction remains the linearization point.

Exact proposed outer layout:

| Item | Exact rule |
|---|---|
| Manifest key | ASCII `RRMP/M1` (7 bytes) |
| Chunk keys | ASCII `RRMP/C0` … `RRMP/C4` (7 bytes each) |
| Manifest value | `RRM1`, schema 1, exactly 256 bytes |
| Chunk maximum | 61,440 bytes |
| Chunk count | 1…5, canonical minimum needed for `total_length` |
| Logical export maximum | 307,200 bytes |
| Platform values over 65,536 | always reject before mutation |
| Unused chunk keys | absent; any extra present key is `EXTRA` |

Proposed manifest fields:

```text
0     4   magic "RRM1"
4     2   schema = 1
6     2   length = 256
8     8   bundle_generation, 1..MAX-1
16    4   total_length, 1..307200
20    1   chunk_count, 1..5
21    3   reserved zero
24   32   SHA-256(exact logical RRMPNS1 bytes)
56  180   five descriptors: length_u32 + SHA-256(chunk), unused all zero
236  16   reserved zero
252   4   CRC32C(full manifest with this field zero)
```

The standard single-writer path reads the manifest and all five chunk keys in
the same READ_WRITE snapshot, compares the exact expected
`(present, manifest bytes, logical length, logical SHA-256)` witness, stages
all desired chunks, erases unused chunks, writes the manifest and commits once
with `FULL`.

The private multi-Controller authority callback must operate on this bounded
piece vector, never on one oversized value. It atomically compares the same
expected witness and replaces the complete manifest/chunk set. Exactly one
caller may succeed for one expected witness.

`COMMIT_UNKNOWN` recovery reads one fresh snapshot and accepts only the exact
OLD or exact NEW manifest plus chunk set. Missing chunk, extra chunk, bad
length/digest/CRC, mixed generation or any third bytes are
`PARTIAL | EXTRA | THIRD` and permanently fence mutation/TX. Definite failure
must restore the exact OLD logical image before returning a non-unknown
failure.

The 21 route and 22 parent physical-key layouts remain the inner canonical
representation carried by `RRMPNS1`. This outer bundle resolves the previous
contradiction: it preserves a single atomic Platform transaction without
pretending a 153,076-byte capacity snapshot is one legal value or attempting a
non-atomic transaction across separately opened handles.

The 307,200-byte ceiling is not an arbitrary arena size. The conservative
simultaneously-live maximum after RRP-2 is:

```text
route one-image baseline
  = 8 + (13+256) + 20*(13+4096)                     =  82,457
parent one-image baseline
  = 8 + (13+256) + 21*(13+4096)                     =  86,566
one unresolved FULL group's retained images
  = 9*(13+4096)                                     =  36,981
QST4 maximum
  = 56 + 64*64 + 124*72 + 64*320 + 16320 + 256*80
    + 64*224                                         =  84,696
RRMPNS header                                            20
                                                            -------
conservative required maximum                          290,720
outer chunk capacity
  = 5*61,440                                          = 307,200
headroom                                               =  16,480
```

Only one unresolved FULL group may exist because the owner is globally fenced
from the first uncertain write until exact OLD/NEW recovery. The maximum
logical mutation count for that group is nine. A second retained group,
mutation while fenced, or export above 290,720 is a contract failure; the
307,200 chunk capacity is transport headroom, not permission to expand a
resource bound silently.

Before accepting a snapshot, the implementation enumerates the exact
`RRMP/` prefix in the same transaction. The only legal keys are `RRMP/M1` and
the canonical `RRMP/C0`…`RRMP/C{chunk_count-1}` set. Unknown, duplicate,
out-of-order, unused-but-present or missing keys classify
`EXTRA/PARTIAL/THIRD`; five point `get` calls alone are not closed-key-set
evidence.

The public single-writer path relies only on the Foundation contract for one
active writer to the exact namespace. The private multi-Controller callback is
versioned separately and must guarantee serializable compare-and-exchange over
the complete manifest/chunk set: two calls with the same expected witness have
at most one `OK`; the loser returns `EXPECTED_MISMATCH`; process failure may
return `COMMIT_UNKNOWN` only after a durable OLD/NEW witness exists. A callback
that provides last-writer-wins, per-key CAS, or an unverified isolation level
is rejected at bind time and cannot enable a multi-Controller claim.

## RRP-2 — durable used-attempt ledger

`RRMPQST4` adds a bounded global used-attempt ledger with 256 entries. Each
entry is exactly 80 bytes and copy-owns:

```text
0   16  owner_scope_id16
16  16  attempt_id16
32   1  lifecycle
33   1  flags
34   6  reserved zero
40  32  terminal_evidence_digest32
72   8  reclaim_not_before_ms_u64
```

The maximum row span is therefore `256 * 80 = 20,480` bytes; QST4 header
length/count/CRC and the complete export resource arithmetic must include it.

Selection first checks the whole live/tombstone ledger, not only the most
recent attempt in a scope. A→B→A is therefore rejected. The ledger survives
restart, higher assignment epoch, parent loss, split brain and handoff.

The QST4 header is exactly 56 bytes. Byte 48 is the durable
authority-global fence, byte 49 is its reason, bytes 50..51 are the attempt
row count, bytes 52..53 are the handoff tuple row count, and bytes 54..55 are
zero. None is a reclaim clock. A
LIVE→TERMINAL_RETAINED transition sets that row's exact
`reclaim_not_before_ms = terminal_observed_now_ms + ATTEMPT_RETENTION_MS`,
where `ATTEMPT_RETENTION_MS = 60,000`.
Overflow fails before mutation.

After the attempt rows, QST4 carries at most 64 lexically ordered exact
handoff tuple rows. Each row is exactly 224 bytes:

```text
0    16  owner_scope_id16
16  104  exact old authority tuple
120 104  exact new authority tuple
```

Every durable scope whose handoff state is non-zero has exactly one row; a
missing, duplicate, extra, non-canonical, or mismatched row rejects the whole
snapshot. This appendix is required because NPA1 is already full and cannot
copy-own both 104-byte tuples. It closes restart continuity for S1 through S6
instead of relying on reconstructing the old authority after NOA1 replacement.

There is no implicit oldest-entry eviction. Selection inserts `LIVE`.
Terminal FULL copies the matching durable completed-evidence digest into the
row and advances it to `TERMINAL_RETAINED`. A private source-only version-2
reclaim operation identifies one exact `(owner_scope_id16, attempt_id16)` row
and may erase it only after a fresh check proves:

- the row is `TERMINAL_RETAINED` and its non-zero digest matches a durable
  COMPLETED evidence record or used handoff tombstone selected by row flags;
- no durable or in-memory queue item refers to the same scope and attempt;
- a handoff row has durable S6/`OLD_RETIRED` plus its used-token tombstone;
- trusted `now_ms >= row.reclaim_not_before_ms`; and
- the authority-global fence is clear.

Caller-supplied digest/proof is never authority. Only the fresh durable
observations above authorize reclaim. Until explicit FULL reclaim succeeds,
capacity exhaustion returns `RESOURCE` before selection or mutation. Only
after that reclaim may the attempt identity be used again; transaction/effect
dedupe remains a separate invariant. A newer terminal row never changes an
older row's deadline; a continuous terminal stream therefore cannot starve
already-mature rows from explicit reclaim.

## RRP-3 — exact old/new authority tuple

Each handoff scope must durably copy-own both tuples:

```text
present
exact NOA1 length
SHA-256(exact NOA1 bytes)
assignment_revision
controller_term
owner_controller_id16
writer_epoch
lease_not_after_ms
authority_clock_epoch_id16
```

`owner_prepare` captures the current active tuple before storing the proposed
new tuple; it may not overwrite the only old witness. `old_fence_proof` binds
the old tuple, scope, handoff token, old revision, writer and proof kind.
Allowed term advancement proof kinds are closed:

1. exact prior-writer explicit resign proof; or
2. trusted-clock observation at/after the exact old lease expiry in the same
   authority clock epoch.

A higher term without one of these proofs is `AUTHORITY_CONFLICT`.

`authority_commit` compares the durable current writer record, complete old
tuple and unused token, then installs the complete new tuple. Its commit digest
binds all of those inputs. Two owners starting from the same snapshot must
produce exactly one success through the real durable bundle CAS. Wrong old
length/digest/revision/writer/term/epoch/lease, stale generation and token
replay all fail before activation.

`parent_set_install` only constructs/revises NPS1. It must validate
`controller_term` against the current authority writer and cannot change the
active NOA1, clear seals, enable downlink or erase used-attempt entries.

## RRP-4 — authority-global split-brain fence

Separate two inputs:

- `authority_writer_conflict`: same authority and term, different active
  writer. Persist a global fence. All scopes have downlink TX 0; route admit,
  selection, worker/provider send and new handoff reject. Cold restart retains
  the fence.
- `scope_parent_anomaly`: duplicate/conflicting parent evidence proven to one
  owner scope. Only that scope is sealed.

Clearing an authority-global fence requires a separately specified durable
authority recovery transition. Parent-set reinstall is never that transition.

## RRP-5 — strict dual-image import

Both route and parent namespace import must enforce:

- header reserved bytes zero;
- each key ID occurs zero, one or two times only;
- generation is non-zero, non-MAX, unique per key and in canonical ascending
  order;
- exact key-kind length, magic, schema, reserved bytes, digest and CRC before
  accepting the image;
- three images, same generation with different bytes, reversed generations or
  invalid inner pages classify `THIRD/CORRUPT` and permanently fence.

Import must not discard an earlier image and then classify the remaining pair
as NEW.

## Required acceptance matrix

1. Generator check/self-test plus independent Python, Node and C authority:
   route=21, parent=22; donor changes to 17, 20 and 23 reject.
2. Real POSIX SQLite full-capacity state: 128 active routes + 64 scopes + 64
   queue entries plus the 256-entry attempt ledger. Exact logical export
   length is ≤274,336 bytes, every observed Platform `put` is ≤65,536 bytes and the outer
   key set is exactly one manifest plus the canonical minimum 1…5 bounded
   chunks; every unused chunk key is absent.
3. Every manifest/chunk `put`, erase and commit fault point with cold reopen:
   exact OLD/NEW only; missing/extra/unknown `RRMP/*` keys and
   PARTIAL/EXTRA/THIRD never publish.
4. Two independent owners from one durable snapshot: exactly one bundle CAS
   and authority commit succeeds.
5. Used attempt: A→B→A, restart A, higher-epoch A, parent-loss A and post-handoff
   old A all reject; a genuinely new attempt succeeds.
6. Parent-set revision cannot clear any seal or select/send without the full
   authority transition.
7. Wrong old tuple field, missing term proof, stale writer, wrong clock epoch,
   premature lease-expiry proof and token replay all reject with mutation/TX 0.
8. Two scopes, then authority-writer conflict: both select, admit, worker,
   provider send and handoff reject before and after cold restart; a
   scope-local anomaly leaves the unrelated scope operational.
9. Three-image, duplicate-generation and reversed-order imports fail in normal
   and ASan/UBSan builds.
10. Feature OFF residuals, tests-OFF install boundary, public ABI/wire
    non-leakage, exact ESP-IDF v5.5.3 compile/link/map and software resource
    gates pass.
11. Real ESP flash power-cut, three-node RF relay, multi-parent failover and
    soak remain explicit `NOT_RUN` until hardware execution.

## Promotion rule

Existing green suites are regression evidence only. RRMP may return to
`HOST_CANDIDATE` only after RRP-1…RRP-5 are reflected in the Proposed ADRs and
machine authorities, all required Host tests pass, and an independent reviewer
reports P0=0/P1=0. `TARGET_CANDIDATE` additionally requires the pinned ESP
target gates. No physical or release-support promotion is allowed from
software evidence.
