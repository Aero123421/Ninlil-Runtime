# Domain schema1 runtime binding tranche-1 repair record

Date: 2026-07-29  
ADR: docs/adr/0022-domain-store-schema1-runtime-binding.md  
Vector: spec/vectors/domain-store-schema1-runtime-binding-v1.json  

## Status agreement

| Artifact | Status |
| --- | --- |
| ADR design | SPEC_ACCEPTED (design only) |
| ADR implementation | incomplete / under independent repair |
| Machine vector | PROPOSED_DOCS_ONLY |
| This repair | addresses Sol re-audit P1=5 P2=2; not a promotion |

## Erratum: bootstrap fixture vs docs/12 Foundation SMALL-1

Previous bootstrap fixture used `role=CONTROLLER` with multi-target, multi-cancel,
nonzero event spool, and `result_cache_retention_ms > terminal_retention_ms`.
That combination is invalid under docs/12. Regenerated fixture is exact valid
Controller + TEST (targets=1, cancel=1, event spool 0/0, result≤terminal).

## Repair inventory

1. Shared Foundation role-aware validator for encode/decode/open/plan.
2. LAST_LAB: full format1 decode + Foundation common validator.
3. Plan/identity flags/epochs validated before any record derivation.
4. Checked size_t count×element_size with hard cap; large u32 paths tested.
5. Bridge pins per-ID bytes/status/transcript/class; self-test donor/partial/computed.
6. Portable CMAKE_NM symbol inventory; OFF=0 / ON=required API set.
7. **count==0** safe: no `SIZE_MAX/count`; exact `out_bytes=0` (UBSan-tested).
8. **Immutable plan seal**: sealed binding/identity/limits/counts + CRC; any
   valid-value ID/limit/retention substitution rejected; records recompute from seal.
9. **Bridge exact map**: independent mutation rebuild; required `computed_status`;
   delete/swap/donor tests; 41 self-test mutations.
10. **CMake exact symbols**: `found == required` (not subset); 12th-prefix self-test.

## Nonclaims

No public ABI, default OFF feature, no LAB publication authority, no T1b–T7 /
HIL / production completion claim.
