# Production Attachment PA-S0 independent review — immutable NO-GO baseline

Date: 2026-07-31  
Scope: Proposed ADR-0023, chapter 35, the PA-S0 vector, and its Python/Node/C11
authorities  
Verdict at review time: **NO-GO — P0=0 / P1=5 / P2=4**

This file records the read-only independent review result before the repair.
Passing the then-current 8 focused tests did not prove these behaviours; those
results were false-green for the findings below.  This baseline verdict is not
rewritten into GO.  A later review must be a separate file and must inspect the
repaired snapshot.

## Findings

| ID | Severity | Finding and original evidence | Required closure | Repair disposition |
| --- | --- | --- | --- | --- |
| `PA-RV-P1-01` | P1 | Re-attachment was hard-coded to exactly eight OLD rows. `observed_old_members()` admitted only N6AL/N6HW and asserted `len == 8`; the envelope and group machine repeated the number. A legal non-empty lane OLD and arbitrary per-row OLD/NEW/STABLE state could not be represented. Original refs: `tools/production_attachment_edhoc_vector_gen.py:1806-1860`, `:3050-3053`, `tools/production_attachment_edhoc_independent_authority.py:147-153`. | Model all 15 write-set rows with `old_present`, old image and proposed new image; admit legal lane OLD; classify OLD/NEW/STABLE/THIRD per row; prove AL floor/HW non-regression through 10,000 restart cycles; remove the exact-eight assumption. | Pending in this immutable baseline. |
| `PA-RV-P1-02` | P1 | Factory Identity, Membership and the local static-DH operator were prose prerequisites, but no exact copy-owned claim/port/state machine made them constructible. Original refs: `docs/35-production-attachment-edhoc-profile.md:52-92`; vector contained only peer credential material under `credentials`. | Define exact prerequisite claims and private operator contract: opaque reference, revision/generation floors, public/private match, role/curve/identity binding, reentry/partial-output failure, no private export, bounded output and zeroization. If upstream modules are not Accepted, remain Proposed and fail closed without claiming the dependency. | Pending in this immutable baseline. |
| `PA-RV-P1-03` | P1 | The machine vector had complete Message 1 rows only; method 3, suites 2/3, Message 4, EAD and downgrade were mainly booleans. Original refs: `tools/production_attachment_edhoc_vector_gen.py:2329-2356`, `:2763-2773`, `:2849-2862`. | Materialize both suite-2 and suite-3 `message_1..message_4` traces, mandatory Message 4 before exporter, non-empty EAD_1..EAD_4 terminal failures and downgrade/no-auto-retry outcomes. Distinguish synthetic profile traces from RFC/provider KAT claims. | Pending in this immutable baseline. |
| `PA-RV-P1-04` | P1 | `NAR1-REORDER-DUPLICATE-LOSS` was recorded by comparing arrays, not by feeding packets through a reassembly owner. The vector exposed fragments but no transition/result transcript. Original refs: `tools/production_attachment_edhoc_vector_gen.py:248-285`, `tools/production_attachment_edhoc_gate.py` prior `validate_fragments()` implementation. | Execute an actual bounded reassembly model and test canonical/reordered success, same duplicate/no progress, conflict, gap, overlap, mixed tuple, loss+timeout discard, and inner/digest mismatch. | Pending in this immutable baseline. |
| `PA-RV-P1-05` | P1 | The stated reassembly owner key omitted the source locator and cookie scratch had no executable quota/idle/bucket-expiry authority. Original refs: `docs/35-production-attachment-edhoc-profile.md:279-312`, vector `stateless_cookie`. | Bind source locator into owner identity. Model per-source/global quotas, exact two-fragment pre-auth scratch, token-bucket admission, idle expiry and cookie-bucket expiry with terminal discard. | Pending in this immutable baseline. |
| `PA-RV-P2-01` | P2 | PA docs prohibited magic collision, but there was no repository-wide registry authority. Original refs: `docs/35-production-attachment-edhoc-profile.md:36-43`. | Add a repository scan/registry gate proving `NAC1`, `NAS1`, `NAR1` unique and rejecting PA reuse of reserved `NPA1`/`NPS1`. | Pending in this immutable baseline. |
| `PA-RV-P2-02` | P2 | NAS1 had one complete positive wrapper; partial-read, short-EOF, trailing bytes, future version and inner-carrier mismatch were not executed as a stream lifecycle. Original refs: `tools/production_attachment_edhoc_vector_gen.py:188-202`, `:2804-2809`. | Add a bounded incremental decoder model and exact close-with-zero-delivery outcomes for every failure family. | Pending in this immutable baseline. |
| `PA-RV-P2-03` | P2 | `production_attachment_edhoc_compose.py` imported the generator and called its `build_document()`, so expected-tree equality did not independently reject coherent generator drift. Original refs: `tools/production_attachment_edhoc_compose.py:14-24`. | Separate the emission CLI from construction and add independent formula/transition authorities plus coherent-drift mutation tests that do not use the generated document as expected truth. | Pending in this immutable baseline. |
| `PA-RV-P2-04` | P2 | The composable-module candidate did not include an actionable Identity/Membership/Production Attachment module plan. | Add the missing dependency/module closure in ADR-0028’s own repair lane. Do not alter that lane from this PA-S0 repair except for a cross-reference. | Pending in this immutable baseline. |

## Mandatory repair acceptance IDs

The repaired PA-S0 candidate must add and execute at least these stable IDs:

- `PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD`
- `PA-REATTACH-LANE-OLD-NONEMPTY`
- `PA-REATTACH-10K-RESTART-MONOTONIC`
- `PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY`
- `PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY`
- `PA-EDHOC-SUITE2-M1-M4`
- `PA-EDHOC-SUITE3-M1-M4`
- `PA-EDHOC-EAD1-EAD4-TERMINAL`
- `PA-EDHOC-DOWNGRADE-NO-AUTORETRY`
- `PA-NAR-REORDER-SUCCESS`
- `PA-NAR-DUPLICATE-NO-PROGRESS`
- `PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT`
- `PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET`
- `PA-MAGIC-GLOBAL-UNIQUE`
- `PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER`
- `PA-INDEPENDENT-COHERENT-DRIFT-REJECT`

## Promotion rule

ADR-0023 remains **Proposed** after repair.  Promotion requires a fresh
independent review of the repaired immutable snapshot with `P0=0 / P1=0`; this
baseline is evidence of the pre-repair state, not an acceptance certificate.

## Post-baseline repair candidate disposition (not a revised verdict)

The following candidate repairs were added after this immutable review.  This
section records traceability only; it does **not** change the NO-GO verdict and
is not a substitute for a fresh independent review.

| Finding | Candidate repair evidence |
| --- | --- |
| `PA-RV-P1-01` | The 15-row inventory now carries per-row `old_present`, OLD value/digest/context and proposed NEW. OLD cardinality is derived, the fixture contains six legal lane OLD rows plus four AL/four HW rows, the marker is absent, OLD/NEW/STABLE/THIRD row cases execute, and a 10,000-cycle restart transcript proves floor/high-water non-regression. |
| `PA-RV-P1-02` | Vector `prerequisites` now contains exact copy-owned Factory Identity/Membership claims, role-separated credential descriptors, the bounded local P-256 static-DH port, nine terminal mismatch/rollback/reentry/partial-output cases, zero private export and zeroization. Dependency readiness remains explicitly unestablished and start fails closed. |
| `PA-RV-P1-03` | `edhoc_attempts` materializes suite 2 and suite 3 Message 1..4 NAC1 records, Message 4-before-exporter, all four non-empty EAD terminal cases and no-auto-downgrade. It labels the traces synthetic and makes no real-provider KAT claim. |
| `PA-RV-P1-04` | Python, Node and C11 now feed canonical, reversed, duplicate, conflicting, missing, overlapping, mixed and inner-mismatch packets through bounded fixed-slot reassembly owners. Failure publication is zero. |
| `PA-RV-P1-05` | NAR/pre-auth owner identity starts with source locator. The machine model fixes per-source 1/global 8 scratch, exact two fragments, capacity/refill 2/2 s, idle 9 s, current/previous cookie buckets and zero identity/credential allocation before cookie. |
| `PA-RV-P2-01` | `spec/protocol-magic-registry-v1.json` and `tools/protocol_magic_registry_gate.py` provide the global collision authority and mutation tests. |
| `PA-RV-P2-02` | Python, Node and C11 execute a bounded 612-byte incremental NAS owner for partial success and short EOF/trailing/future/inner-carrier close with zero delivery. |
| `PA-RV-P2-03` | The emission CLI is thin; construction lives in `production_attachment_edhoc_composition.py`; semantic authority lives in the separate independent/R6/expected-model modules. Twelve repaired coherent-drift trials and exhaustive Python/Node leaf campaigns reject drift. |
| `PA-RV-P2-04` | Not owned by this repair. ADR-0023/docs 35 now cross-reference ADR-0028; Identity/Membership/Attachment module closure must be reviewed in ADR-0028’s own lane. |

Candidate evidence at the repaired working snapshot:

- vector SHA-256:
  `f9cef8d9d9ea74b4914d9dcae5562df9f6b9583dc28f0ed238adde2d3765806e`
- focused normal CTest: 10/10 PASS
- strict standalone C11: 70/70 case ledger PASS
- sanitizer C11 CTest: 1/1 PASS
- Python exhaustive campaign: 8,324 total mutations / 7,458 scalar-leaf
  mutations, 767/767 unknown-key rejections, 0 false-greens
- Node exhaustive campaign: 8,319 total mutations / 7,458 scalar-leaf
  mutations, 767/767 unknown-key rejections, 0 false-greens

Still pending: fresh independent re-review, real provider/crypto KAT,
production owners and physical Linux/macOS USB, ESP32-S3 Wi-Fi and
ESP32-S3+SX1262 HIL. ADR-0023 therefore remains **Proposed**.
