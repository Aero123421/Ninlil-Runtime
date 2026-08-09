# Production Attachment PA-S0 software closure

Date: 2026-08-10  
Status: **software gate closed; ADR-0023 remains Proposed**

The final PA-S0 repair replaces postulated local-key failure rows with a valid
typed baseline and nine single-cause transitions. Independent Python, Node.js,
and C11 machines bind each failure ID to the exact changed input and reject
ID/input swaps or rotations. The EAD negative matrix now consumes distinct
stage-owned bytes and rejects empty, duplicate, collapsed-stage, and swapped
variants.

An independent Sol xhigh review returned
`GO — P0=0 / P1=0 / P2=0 / P3=0`; its immutable evidence is recorded in
[`../reviews/2026-08-10-production-attachment-pa-s0-closure-review.md`](../reviews/2026-08-10-production-attachment-pa-s0-closure-review.md).

This checkpoint does not implement EDHOC crypto, an Attachment owner, Join,
Composition activation, ESP execution, or HIL. Those remain PA-S1 through
PA-S6 work.
