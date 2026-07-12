# D3-S2 oracle self-test performance record

Date: 2026-07-12  
Scope: `tools/domain_scan_crossrow_d3s2_vector_gen.py`  
Authority impact: none（Normative / JSON / C fixture / production code unchanged）

## Outcome

The cross-row oracle self-test retains all 232 negative tamper cases, the clean
pass, downgrade guard, prefix freezes, and independent public CLI check while
reducing local wall time from **167.77 s** to **4.70 s**（about 97%）。

| Evidence | Before | After |
| --- | ---: | ---: |
| self-test wall time | 167.77 s | 4.70 s |
| Python calls（cProfile） | 145,795,665 | about 7 million |
| tamper checks | 232 | 232 |
| Debug full ctest | about 240 s | 13.97 s（86/86） |
| ASan/UBSan full ctest | about 245 s | 18.66 s（86/86） |

Environment: macOS, Python 3.14.6. GitHub runner timing is expected to differ;
the invariant is the preserved checks and deterministic output, not a fixed
wall-clock threshold.

## Cause

Every tamper previously rebuilt the same deterministic 133-vector expected
document and frozen D3-S1 prefix. cProfile showed 235 `build_document` calls,
469 `freeze_d3s1_prefix` calls, and repeated D1 authority validation. Most CPU
time was repeated upstream vector generation and CRC32C work unrelated to the
individual mutation.

## Optimization boundary

- Public `check <path>` still starts cold and independently rebuilds the
  expected document and D3-S1 prefix.
- Only `self_test` injects one previously generated and independently verified
  expected document/prefix pair into subsequent tamper checks.
- Partial injection（expected only or prefix only）is rejected.
- Every tamper still reloads the clean JSON into an independent object.
- SHA-256 canaries prove the shared expected document and prefix remain
  unchanged across all tampers.
- D1 catalog data is read-only and its authority pin is fully verified once per
  process. Separate CLI invocations do not share cache state.

## Verification

- generator `check` and `self-test`: pass
- regenerated JSON vs committed JSON: byte-identical
- Debug: 86/86
- ASan/UBSan: 86/86
- tests-OFF/private gates: pass
- `git diff --check`: clean

This change improves CI headroom only. It does not advance D3-S2 completion
status or change any Runtime behavior.
