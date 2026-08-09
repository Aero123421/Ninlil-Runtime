# Production Attachment PA-S0 software-closure review

Date: 2026-08-10  
Reviewer: Codex GPT-5.6 Sol xhigh, read-only  
Scope: PA-S0 vector, generator, independent Python authority, Node gate, and C11 gate  
Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**

## Reviewed snapshot

- base HEAD: `fcd1fef0bbbf3cee4742a59cb56c910127b384a7`
- scoped patch SHA-256: `764d1ad5443313cac83d68862cb1e27c870316e3c557ceba51b9438bdfdfeb6a`
- canonical vector SHA-256: `ba5ed7fa643679d21f399f505af3102dc500b693b108ce1a0cee27b9b3f8089e`

The simultaneous PA-S1a dependency work was excluded from this verdict.

## Closed findings

1. The nine local static-DH cases now contain one valid baseline and nine
   concrete typed input/provider-behaviour deltas. Python, Node.js, and C11
   derive the result from the inputs rather than trusting the row ID or stored
   counters. Each implementation separately binds every failure ID to its
   exact field and value and rejects ID-preserving input swaps and rotations.
2. `EAD_1_NONEMPTY` through `EAD_4_NONEMPTY` form an exact ID/stage/consumed-byte
   bijection. The three implementations reject empty, duplicate, all-stage-1,
   and swapped-input variants.
3. The earlier protocol-magic coverage finding remains closed by the exact
   occurrence/path registry and its alternate-representation mutants.

The reviewer injected the swap/rotation probes directly into the independent
Python authority, Node gate, and C11 machine. All were rejected. No shared
validator was introduced, and the Ponytail review found no additional layer
or deletion candidate.

## Reproduced evidence

- focused normal CTest: **10/10 PASS**;
- ASan/UBSan C11: **1/1 PASS**, `executed_cases=70`;
- Python mutation campaign: **9514**, false greens **0**;
- Node mutation campaign: **9509**, false greens **0**;
- closed object paths: **850/850** unknown-key rejection;
- Python syntax, Node check, fixture freshness, vector generation, and
  `git diff --check`: PASS.

## Status boundary

This is PA-S0 software-closure evidence only. ADR-0023 and chapter 35 remain
**Proposed**. PA-S1 through PA-S6, real suite-2/3 crypto and credentials,
Production Attachment owners, direct Join, cold multi-hop Join, target
execution, physical HIL, field/legal evidence, and release support remain open.
No public API or feature maturity was promoted by this review.
