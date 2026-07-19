# R6 secure radio wire freeze — self-review (round 4 repair candidate)

**Date:** 2026-07-18  
**Status:** docs-only **Accepted 仮**; **not GO**; independent re-audit still NO-GO until P0=P1=P2=0.  
**Not claimed:** R6 complete, R7 C codec/AEAD, HIL, Japan legal, production radio, ESP full capacity, schema2 loader shipped, production HAL reasons 43/44/45 present.

## Scope

Normative: [docs/30](../30-r6-secure-radio-wire.md), [ADR-0010](../adr/0010-r6-secure-radio-wire.md), amended [docs/24](../24-r2-physical-compliance-permit-authority.md) / [docs/29](../29-r5-lab-only-profile-loader.md), `tools/radio_wire_r6_docs_gate.py`.

## Independent audit → fix mapping

| Cluster | Audit theme | Fix in freeze |
| --- | --- | --- |
| consume | docs/24 §10.10 generic reason 41 rows | sole table: PCP 9/43/44/45 → HAL 16/43/44/45 |
| catalogs | R2 PCP vs R1 HAL conflation | explicit two-catalog mapping; 16 is HAL-only |
| clock | Algorithm A A2 durable=0 | shared F_c FULL helper; empty→FENCED after FULL |
| adopt | opaque token marker | 120 B only; marker forbidden |
| retry | generic UNCONSUMED target | typed HAL 16/45 only for same-Permit |
| capacity | vague ESP formula | exact entries/bytes equations; max_namespaces=2 NOT READY |
| layouts | prose N6 keys | byte-exact N6RT/N6CF/N6HW key+value tables |
| join/GC | directionful allocator / phantom paired N6AL | direction-independent allocator + actual-side-only N6AL; one context unit per FULL; GC ≤32 |
| CU | non-OK close claim | close void only; rollback status; get shape CORRUPT |
| events | terminal dual / LENGTH_CLASS overlap | exactly one terminal signal; FRAME_READY vs LENGTH_CLASS |
| structure | orphan tails | docs/30 ends at Related; docs/29 §5.3 before Packaging |

## Gate

`radio_wire_r6_docs_gate` uses structural checks + destructive mutations targeting the above (timer-domain table set-equality and resource tables remain in docs/30). Gate does not claim detection of arbitrary natural-language contradictions. Mutation count is whatever `--self-test` prints.

## Residual R7 blockers

- C implementation: private issue/adopt/F_c helper, event bus, schema2 loader  
- R1 HAL reasons 43/44/45 absent in production headers (current 41/42 legacy)  
- ESP `max_namespaces=2` < required 3  
- Vector materialization `spec/vectors/r7-radio-wire-v1.json`  
- docs/25 fence resolution (untouched)

## Round 4 (still not GO)

| Fix | Content |
| --- | --- |
| N6AL allocator | 26 B fingerprint excludes direction; key byte3 reserved zero; actual local side only |
| GC M | `(epoch, layer, receiver, alloc_side)`; context-unit deletion includes the one N6AL and present N6HW records |
| catalogs | typed map not bit-exact; TX_RESULT result_catalog required |
| adopt prove | old_present=1 fixed; absent meta is CORRUPT; proposed match → DURABLE_META_PROOF |
| baseline/CLOCK | publication and trusted baseline separated; state2 initial-untrusted; two-axis mutation; unpublished no-sample |

## Round 4 verdict

**Still not GO.** Round 4 closes false-green doc contradictions only. Event/seal/callback/multi-PC dispatch and N6 lifecycle require independent zero-finding re-audit. No production completion claim.
