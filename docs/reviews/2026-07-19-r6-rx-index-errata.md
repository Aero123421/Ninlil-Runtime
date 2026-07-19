# R6 accepted-source errata — RX/TX lane index bounds (non-normative review)

**Date:** 2026-07-19  
**Branch:** `codex/r6-rx-index-errata`  
**Class:** non-normative review record; Normative behavior = **docs/30 §20.12**; ADR-0010 records limited host pin withdrawal + candidate pin  
**Status:** errata **implemented and re-accepted** for the R6 host source pin; fresh root QA **green** after the live-CU `n_keys=0` repair; independent final re-review **GO (P0=0 / P1=0 / P2=0)**; official GCC13 and ESP-IDF CI **green**; **not** product GO

## Discovery

GitHub CI / independent review with **GCC 13 `-O2` strict** and subsequent independent review established a real fail-closed gap:

- file: `src/radio/n6_context_store.c`
- `n6_rx_precheck_window` / admit / `tx_burn`: `idx = n6_lane_idx(...)` may be **`-1`** without range guard → OOB (**P1** on internal admit authority)

## Limited pin withdrawal and re-acceptance

| Path | Pre-errata SHA-256 | Post-errata |
| --- | --- | --- |
| `src/radio/n6_context_store.c` | `4686edcb…` (**limited temporary withdrawal** of Chunk D host pin GO) | `bc8633657a1033fb16cc473794ad8cfab54b17ec00a741814682194d5c7789f6` (**re-accepted R6 host source pin**; gate+docs/07 lockstep, official GCC13 CI and independent final review green) |
| `src/radio/n6_context_store.h` | `1901a595…` | **byte-stable** (unchanged) |
| `src/radio/n6_crypto_host.c` | unchanged | unchanged |

**R6 docs freeze / wire Accepted remains in force.** Only the Chunk D **host source pin** axis was temporarily withdrawn and is now re-accepted at the post-errata hash.  
The re-acceptance conditions are satisfied by official GCC13 CI and independent re-review. Historical reviews are **not** rewritten.

## Fix summary

| Item | Behavior |
| --- | --- |
| Named count | `N6_PRIVATE_NAMED_LANE_COUNT` + 6 array dimensions + 6 `_Static_assert` |
| Guards | window / precheck / admit range / admit layer / tx_burn before array access |
| External invalid / cross-layer | `INVALID_ARGUMENT`, ticket zero, **all 12 mem storage counters delta 0** |
| Internal invalid / catalog-valid cross-layer | `CORRUPT` + fence + full ticket wipe + I/O0 + window snapshot equal |
| CU envelope (rule 7) | full plan preflight + array-post integrity **before** classify I/O; side/key/codec/identity/`post_u64_*`; fail → force-close once → FENCED wipe → `CORRUPT`, **12 counters** with close-only delta when handle was open, zero posts |
| Test seams | `NINLIL_N6_TEST_BUILD` + test TU `extern` only (header byte-stable); per-field CU mutate seam |
| Structural gate | C lexical mask (comment+string+char); exact `n6_lane_idx` branch association (DATA/E2E→`return 0`, ACK→`return 1`, default→`return -1`); exact `n6_lane_ok_for_slot` predicates; exact 6 `_Static_assert` exprs; complete live (non-`if(0)`/`0&&`) true-no-CU, CU preflight, and **rule7b full live if-predicate pin** (post filter/op+old_present/vlen/canary/live/side/range/lane/layer/encode/canon key/TX·RX decode+identity+post_u64+order); **dual exact-pin** of both live `if (e->post == N6_CU_POST_TX_LIMIT)` selectors in `n6_cu_validate_array_posts` with brace-role association (slot-side then/else → TX/RX alloc_side; decode then/else → TX/RX decode+identity+post_u64+order; set membership alone insufficient); **87** pin+docs co-update structural RED mutations (self-test; includes single-site invert ×2 + both-sites invert) |
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

## CI (accepted runner evidence)

`ubuntu-gcc-release-n6-frame` is the OSS GCC13 authority job:

- exact major 13, Release `-O2`, shared SQLite, `compile_commands`
- production compile gate (not testbuild)
- core R6 **14** CTests exact-once + supplemental `n6_gcc13_release_compile_gate_self_test` exact-once
- unfiltered full CTest once
- clang-sanitizers unchanged

Official authority evidence is [CI run 29673619672](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/29673619672): exact GCC 13 `-O2`, production compile-command gate, all-target strict build, required-test identity and unfiltered full CTest are green. [ESP-IDF run 29673619686](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/29673619686) is also green.

## Verification (implementer worktree)

| Check | Result |
| --- | --- |
| Host `ninlil_n6_context_store_test` | **PASS** (**54** cases; includes `rx_lane_idx_errata` + `cu_post_lane_idx_errata` + `tx_burn_lane_idx_errata` + full CU envelope field KATs) |
| Full CTest Release strict | **PASS 183/183** |
| `n6_storage_callsite_gate` check + self-test | **PASS** (structural RED=**87** pin-co-update; total designed RED=**114**; GREEN-keep=**2**; rule7b full live if-predicate pin + dual post-TX selector exact-pin/role association + single-site invert ×2 RED; true-no-CU / preflight / DATA·E2E↔ACK / mask_c_lexical direct) |
| `n6_gcc13_release_compile_gate` self-test | **PASS** (local synthetic; GREEN≈6 / RED=34; absent exact testbuild out-of-authority GREEN when production exists; testbuild-only still RED; symlink in existing testbuild output prefix RED; external production/testbuild suffix + output/-o disagree false-GREEN regressions included) |
| ASan/UBSan focused store test | **PASS** (54 cases) |
| tests-OFF packaging | **PASS** (fresh Release; `ctest -N=0`; bare-all private archive absent; explicit target archive exact; N6 members exact-once; fixture/test/oracle/spy 0; `nm`/`strings` leakage 0; install public-only) |
| `radio_wire_r6_docs_gate` | **PASS** (via full CTest) |
| `git diff --check` | **PASS** |
| Official GCC 13 CI authority job | **PASS** ([29673619672](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/29673619672); exact GCC13 `-O2`, production gate, all-target strict build, required identity, unfiltered full CTest). Includes R5 `profile_loader.c` NULL-proposed alias-gate port, resource-ledger fail-closed total propagation and padding-independent semantic test comparisons discovered by the authority run. |
| Independent final re-review | **GO — P0=0 / P1=0 / P2=0** (store/CU envelope, dual-selector structural pin, R5 alias port, absent-testbuild compile-gate handling, resource-ledger status propagation and semantic test comparisons all independently re-reviewed) |

## Residual P2 close (structural dual post-TX selector pin) + R5 GCC13 alias port

| Item | Status |
| --- | --- |
| Dual exact-pin of both `if (e->post == N6_CU_POST_TX_LIMIT)` in `n6_cu_validate_array_posts` | **implementer closed** (gate + self-test KATs; slot-side / decode roles brace-associated) |
| Single-site invert RED (slot-only + decode-only) + both-sites KAT retained | **implementer closed** (structural RED **87** = 85+2; total designed RED **114**) |
| `n6_context_store.c` / test hashes | **unchanged** (candidate store pin byte-stable this pass) |
| R5 `profile_loader.c` NULL-proposed alias gate (GCC13 `-Wmaybe-uninitialized`) | **implementer closed** (port of `src/radio/profile_loader.c` portion of `858c202` only; no R7 crypto/test) |
| Independent re-review of this residual-P2 + R5 port | **GO — P0=0 / P1=0 / P2=0** |
| Official GCC13 CI re-run | **PASS** ([29673619672](https://github.com/Aero123421/Ninlil-Runtime/actions/runs/29673619672)) |

## Non-claims

- R6 host source pin is re-accepted, but this is **not product GO** or Ninlil-wide completion  
- Independent re-review is **GO (P0=0 / P1=0 / P2=0)** for the complete accepted delta  
- Official GCC13 and ESP-IDF CI are green; local AppleClang and Ubuntu GCC13-container checks remain supplemental evidence  
- Not R7/M4/M5/ESP capacity/HIL/legal/production complete  
- Not public ABI / wire / layout / schema change  
- gate PASS ≠ product GO
