# MFDT Application-handoff amendment independent review

Review date: 2026-08-01  
Scope: ADR-0021 Application-handoff amendment revision 2 and its machine authority  
Verdict: **GO — SPEC_ACCEPTED; P0=0 / P1=0 / P2=0**

## Review progression

The initial independent review was NO-GO and reported normative findings at
P0, P1, and P2.  The repair closed:

- P0: target-local sidecar pre-arm and the later Foundation admission FULL now
  have one exact ordering, failure, `COMMIT_UNKNOWN`, and restart contract;
- P1: duplicate target Runtime handling is deterministic and rejects before
  entropy or durable mutation while preserving the existing public result;
- P2: the public delivery token and private MFDT publication token are named
  and scoped without creating a third token or public API.

A limited independent re-review of those repaired boundaries found no
remaining issue: **P0=0 / P1=0 / P2=0**.

## Reproduced evidence

- The generated authority contains the exact closed inventory: **116/116**
  required vector IDs, with no missing, extra, duplicate, or substituted ID.
- Generator, independent Python, independent Node, independent C11, and
  acceptance check/self-test paths pass.
- A fresh root CMake build reports **CTest 10/10 passed** for the dedicated
  MFDT specification-authority suite.

## Acceptance boundary

This verdict accepts the Application-handoff amendment as a normative
specification only.  The revision-2 OPEN codec, Application Service apply and
Receipt integration, cold-restart correlation/reconciliation, ESP32-S3 target
execution, physical HIL, public ABI, default-ON behavior, and release support
remain incomplete and are not inferred from these tests.
