# R6 accepted-source errata — RX/TX lane index bounds (non-normative review)

**Date:** 2026-07-19  
**Branch:** `codex/r6-rx-index-errata`  
**Class:** non-normative review record; Normative behavior = **docs/30 §20.12**; ADR-0010 records limited host pin withdrawal + candidate pin  
**Status:** errata **implemented** on host candidate; fresh root QA **green** after the live-CU `n_keys=0` repair; independent final re-review **pending**; **source pin re-accept still pending official GCC13 CI**; **not** product GO

## Discovery

GitHub CI / independent review with **GCC 13 `-O2` strict** and subsequent independent review established a real fail-closed gap:

- file: `src/radio/n6_context_store.c`
- `n6_rx_precheck_window` / admit / `tx_burn`: `idx = n6_lane_idx(...)` may be **`-1`** without range guard → OOB (**P1** on internal admit authority)

## Limited pin withdrawal + candidate (not re-accepted)

| Path | Pre-errata SHA-256 | Post-errata |
| --- | --- | --- |
| `src/radio/n6_context_store.c` | `4686edcb…` (**limited temporary withdrawal** of Chunk D host pin GO) | `bc8633657a1033fb16cc473794ad8cfab54b17ec00a741814682194d5c7789f6` (**candidate / NOT YET ACCEPTED** lockstep in gate+docs/07; GCC13 CI + fresh independent final review pending) |
| `src/radio/n6_context_store.h` | `1901a595…` | **byte-stable** (unchanged) |
| `src/radio/n6_crypto_host.c` | unchanged | unchanged |

**R6 docs freeze / wire Accepted remains in force.** Only the Chunk D **host source pin** axis is withdrawn→candidate.  
**Re-accept later** (status-only append after): official GCC13 CI green **and** independent re-review. Historical reviews are **not** rewritten.

## Fix summary

| Item | Behavior |
| --- | --- |
| Named count | `N6_PRIVATE_NAMED_LANE_COUNT` + 6 array dimensions + 6 `_Static_assert` |
| Guards | window / precheck / admit range / admit layer / tx_burn before array access |
| External invalid / cross-layer | `INVALID_ARGUMENT`, ticket zero, **all 12 mem storage counters delta 0** |
| Internal invalid / catalog-valid cross-layer | `CORRUPT` + fence + full ticket wipe + I/O0 + window snapshot equal |
| CU envelope (rule 7) | full plan preflight + array-post integrity **before** classify I/O; side/key/codec/identity/`post_u64_*`; fail → force-close once → FENCED wipe → `CORRUPT`, **12 counters** with close-only delta when handle was open, zero posts |
| Test seams | `NINLIL_N6_TEST_BUILD` + test TU `extern` only (header byte-stable); per-field CU mutate seam |
| Structural gate | C lexical mask (comment+string+char); exact `n6_lane_idx` branch association (DATA/E2E→`return 0`, ACK→`return 1`, default→`return -1`); exact `n6_lane_ok_for_slot` predicates; exact 6 `_Static_assert` exprs; complete live (non-`if(0)`/`0&&`) true-no-CU, CU preflight, and **rule7b full live if-predicate pin** (post filter/op+old_present/vlen/canary/live/side/range/lane/layer/encode/canon key/TX·RX decode+identity+post_u64+order); **85** pin+docs co-update structural RED mutations (self-test) |
| Compile gate | production `ninlil_runtime_private.dir` output selection; gcc-13 / unique `-O2`; self-test + CI |

### Storage I/O0 oracle (exact) — all 12 operations / 12 counters

`n6_mem_storage` exposes **exactly 12** call counters for the full storage ops surface (**includes erase**):

| # | Counter |
| --- | --- |
| 1 | `close` |
| 2 | `open` |
| 3 | `begin` |
| 4 | `iter_open` |
| 5 | `iter_close` |
| 6 | `iter_next` |
| 7 | `commit` |
| 8 | `rollback` |
| 9 | `get` |
| 10 | `put` |
| 11 | **`erase`** |
| 12 | `capacity` |

`test_rx_lane_idx_errata` snapshots all **12** before/after external 0/4/255, both cross-layer directions, internal range-invalid, and internal catalog-valid cross-layer paths and requires **exact equality**. CU envelope KATs require force-close **once** (close delta 1 when the COMMIT_UNKNOWN handle was open) and **delta 0** on open/begin/get/put/**erase**/commit/rollback/iter_*/capacity, with all 3 lane × (TX2 / RX4) arrays unchanged. With every non-close storage call delta 0, durable mutation and array posts are impossible on those fail-closed paths.

## CI (pending runner success)

`ubuntu-gcc-release-n6-frame` is the OSS GCC13 authority job:

- exact major 13, Release `-O2`, shared SQLite, `compile_commands`
- production compile gate (not testbuild)
- core R6 **14** CTests exact-once + supplemental `n6_gcc13_release_compile_gate_self_test` exact-once
- unfiltered full CTest once
- clang-sanitizers unchanged

**GitHub runner not executed from this implementer host.** Keep status **CI pending**.

## Verification (implementer worktree)

| Check | Result |
| --- | --- |
| Host `ninlil_n6_context_store_test` | **PASS** (**54** cases; includes `rx_lane_idx_errata` + `cu_post_lane_idx_errata` + `tx_burn_lane_idx_errata` + full CU envelope field KATs) |
| Full CTest Release strict | **PASS 183/183** |
| `n6_storage_callsite_gate` check + self-test | **PASS** (structural RED=**85** pin-co-update; total designed RED=**112**; GREEN-keep=**2**; rule7b full live if-predicate pin + audit-7 if0/invert RED; true-no-CU / preflight / DATA·E2E↔ACK / mask_c_lexical direct) |
| `n6_gcc13_release_compile_gate` self-test | **PASS** (local synthetic; GREEN≈5 / RED=31; external production/testbuild suffix false-GREEN regressions included) |
| ASan/UBSan focused store test | **PASS** (54 cases) |
| tests-OFF packaging | **PASS** (fresh Release; `ctest -N=0`; bare-all private archive absent; explicit target archive exact; N6 members exact-once; fixture/test/oracle/spy 0; `nm`/`strings` leakage 0; install public-only) |
| `radio_wire_r6_docs_gate` | **PASS** (via full CTest) |
| `git diff --check` | **PASS** |
| Official GCC 13 CI authority job | **pending / not run on this host** |
| Independent final re-review | **pending** (gate/selftest/docs bytes changed for rule7b complete live if-predicate pin; not closed by this implementer pass) |

## Non-claims

- Not product GO; not host pin re-accepted until official GCC13 CI and fresh independent re-review are green  
- Independent re-review remains **pending** after this gate-only residual-P2 close (new gate/selftest/docs bytes)  
- Official GCC13 CI remains **pending**  
- Not R7/M4/M5/ESP capacity/HIL/legal/production complete  
- Not public ABI / wire / layout / schema change  
- gate PASS ≠ product GO  
