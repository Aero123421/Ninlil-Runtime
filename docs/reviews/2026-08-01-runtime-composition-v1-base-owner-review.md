# Runtime composition v1 base owner review

Date: 2026-08-01  
Reviewer: independent Codex reviewer, review-only  
Decision: **GO — P0=0 / P1=0 / P2=0**

## Reviewed scope

- public `composition_v1` workspace/create/access/step/close/destroy owner;
- Runtime terminal owner to Fabric release boundary;
- bounded progress and aggregate `more_work` behavior;
- public C/C++ header and ABI manifest coverage.

## Findings closed

- Runtime work remains visible when its work budget is zero.
- A corrupt terminal row does not advance the retry cursor.
- A transaction terminalized below the current cursor schedules one bounded
  wrap pass, so terminal release cannot be stranded when the owner sleeps on
  `more_work == 0`.
- The public header is covered by C11/C++17 self-contained gates, and its two
  constants and two value types are covered by ABI drift/golden checks.

## Verification

The focused Fabric, terminal projection, composition and ABI set passed
**28/28** in the strict normal build and **28/28** under ASan/UBSan.

This GO covers the base owner only. Sidecar recovery, MFDT/FRAG/relay/
multi-parent composition, installed composition E2E and all physical HIL are
separate gates. Physical evidence remains `NOT_RUN`.
