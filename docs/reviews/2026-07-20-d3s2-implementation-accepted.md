# D3-S2 implementation — Accepted review record (non-normative)

**Date:** 2026-07-20  
**PR:** [#105](https://github.com/Aero123421/Ninlil-Runtime/pull/105) (`codex/d3s2-p1e-formal`)  
**Fixed candidate SHA:** `39e4752ba09637d40d1b2c4c64fbc17ccc872451`  
**Merge SHA (PR #105):** `ca02e24ea7af29c0031366544158a0a21be899bb`  
**状態:** **Accepted — D3-S2 declared multi-count implementation complete only**（D3 incomplete / Stage 5 未接続）

本 record は **非規範** である。Normative 正本は `docs/17-foundation-domain-store.md` §18.13（S2a freeze）と §18.2 / §18.13.19（current status）。新 ADR は不要。

## Supersession

| record | role |
| --- | --- |
| [2026-07-12 D3-S2 completion audit](2026-07-12-d3s2-completion-audit.md) | **historical NOT COMPLETE snapshot** @ `8205afc`（94+18）。本文は改竄しない。 |
| [2026-07-12 D3-S2 post-P0 re-audit](2026-07-12-d3s2-post-p0-reaudit.md) | **historical NOT COMPLETE snapshot** @ `fec9edb`（94+25）。本文は改竄しない。 |
| **本記録（2026-07-20）** | 固定 candidate `39e4752` / merge `ca02e24` / PR #105 上で **formally supersede** する。historical 2026-07-12 records は **NOT COMPLETE の当時 snapshot** として保持する。 |

## Independent review result

| review | P0 | P1 | P2 | verdict |
| --- | ---: | ---: | ---: | --- |
| Sol high P1-E re-review | 0 | 0 | 0 | **GO** |
| Grok high full 21-case fixed-candidate audit | 0 | 0 | advisory | **verdict A**（§18.13.15 cases 1..21 closed） |
| Sol high status-delta initial review | 0 | 0 | 2 | **NO-GO**（文書表現2件; 実装根拠へのblocking指摘なし） |
| Sol high status-delta P2 closure re-review | 0 | 0 | 0 | **GO**（initial P2 2件 closed） |

Grok監査のP2助言は、current-status文言の遅れ（本trancheで解消）と、true-primary raw-only負例およびMode21 CLEANUP green専用IDを別IDへ増やさず既存のPVD/pair-raw・Mode21 pair-absent・Mode22 green経路で閉じるという証拠表現上の注意である。blocking P0/P1はなく、実装追加不要の**verdict A**は維持された。P2を0件と偽って記録しない。

## Official CI evidence（fixed candidate）

| workflow | event | run | jobs | result |
| --- | --- | ---: | ---: | --- |
| CI | push | `29703203477` | 11 / 11 | success |
| CI | pull_request | `29703204524` | 11 / 11 | success |
| ESP-IDF | push | `29703203444` | 1 / 1 | success |
| ESP-IDF | pull_request | `29703204502` | 1 / 1 | success |

## Local CTest evidence

| profile | result |
| --- | --- |
| Root local Release | **225 / 225** |
| Root local ASan/UBSan | **221 / 221** |

**Known infrastructure note:** 並列 local CTest で変更外 profile / n6 共有 temp 競合を **1 回** 観測した。直列全件と official CI は green。これは D3-S2 product defect ではなく known local harness/infrastructure noise として記録する。

## Authority / product pins

| item | value |
| --- | --- |
| Path | `spec/vectors/domain-scan-crossrow-v1.json` |
| Format | `ninlil-domain-scan-crossrow-v1-d3s2` |
| `vector_count` | **144** = d3s1 prefix **94** + d3s2 suffix **50** |
| Canonical `content_sha256` | `a9fccb12d932f0082111c94da3a23cd6680dc4bedecb2108e739bdca55d80fed` |
| Full JSON（raw）sha256 | `e270743e99189a830b1b39d6c4b464fc3d2eb63ff8fe2b20dcfa7ae0f91d01ec` |
| Independent generator | `tools/domain_scan_crossrow_d3s2_vector_gen.py`（production C 非 invoke） |
| Production bridge | `tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` |
| Mutation | **0** |
| Context | sizeof **306** / ceiling **320** |
| Sessions | modes **21..26** = **6** self-contained sessions; 1 session = 1 mode = 1 same `READ_ONLY` txn |
| DSD1 | `spec/vectors/domain-scan-dsd1-composition-v1.json` / format `ninlil-domain-scan-dsd1-composition-v1-d3s2` / **7** sessions（S1 11/14/17/19 + S2 22/23/24） |
| Private surface | `ninlil_domain_scan_begin_profiled_d3s2` 等 private only; public Runtime ABI 追加なし |
| Aggregate ceiling path | **9152**（S1+S2 co-resident path; Stage5-alone 8704 / scanner 8192 unchanged） |

## §18.13.15 case classes 1..21 — closed matrix（concise）

| # | Case class | Close path（representative） |
| ---: | --- | --- |
| 1 | Modes 21–26 positive ordinary counts | empty smokes + positives: `D3S2_M21_STATE_CUM1_…` … `D3S2_M26_ES_R1_…` |
| 2 | SHA multi-owner interleave | `D3S2_M25_TWO_OWNER_SHA_INTERLEAVE_DUAL_CARRIER_OK`（+ Mode23 multi-owner） |
| 3 | Known-slot matrix + illegal slot/kind | Mode23/24/25 positives + `D3S2_M23_ILLEGAL_SLOT_L_PLUS_1_BIND_CORRUPT` |
| 4 | Stream under/over count | Mode21 app/cancel/index + Mode22 under + Mode26 overcount vectors |
| 5 | CLEANUP_PLAN PRESENT skip / still ordinary | Mode21 pair-absent + Mode22 cleanup skip OK + Modes 23–26 still ordinary CORRUPT |
| 6 | Carrier cursor no-skip/no-dup | dual-carrier interleave + multi-owner Mode23 cursor paths |
| 7 | Same-txn multipass; two-txn harness fail | every d3s2 vector `begin_calls==1`; generator self-test two-txn anti-pass |
| 8 | BIND primary/PVD/raw/pair / Mode22 INDEX | Mode21 PVD/raw + Mode22 unexpected INDEX + true-primary ABSENT |
| 9 | BIND missing carrier / orphan | Mode22–26 carrier-ABSENT orphans |
| 10 | Count green without BIND must not pass | `D3S2_M21_COUNT_GREEN_BIND_INCOMPLETE_FALSE_TERMINAL_OK` |
| 11 | Port terminal mid-FOCUS/BIND note 0 | P0-C BIND get + **P1-E** mid-FOCUS `D3S2_M26_MID_FOCUS_ITER_NEXT_PORT_FAILURE_NOTE0` |
| 12 | Profile mismatch / future → evaluator off | `D3S2_M21_PROFILE_MISMATCH_EVALUATOR_OFF` / `…_FUTURE_PROFILE_…` |
| 13 | Budget mid-focus same-session resume | `D3S2_M26_ES_MGMT_BUDGET_MID_FOCUS_RESUME_OK` |
| 14 | Empty secondary / empty-carrier BIND | empty×6 COMPLETE + undercount empty-secondary vectors |
| 15 | Mode22 INDEX ABSENT path; Mode21 BIND_INDEX | Mode22 success + unexpected INDEX CORRUPT; Mode21 INDEX get budget |
| 16 | Mode25 RECENT-without-CUM; CUM primary-only | `…_REC_WITHOUT_CUM_…` + `…_CUM_T1_REC_S1_…` |
| 17 | DSD1 multi-session composition | DSD1 7-session composition sibling + production bridge |
| 18 | exact 94 d3s1 prefix retained | generator check + bridge pin `NINLIL_D3S1_VECTOR_COUNT==94` |
| 19 | Mode23 equation + late coherence | success equation + `…_EQUATION_FAIL_…` + `…_LATE_COHERENCE_…` |
| 20 | Six-session product honesty | six independent empty smokes; no one-baseline-all-six |
| 21 | Get-budget freeze | bridge compares `d3_peer_get_count`; generator per-row ≤3 / Mode21 INDEX≤2 |

### P1-E residual close（case 11）

| item | evidence |
| --- | --- |
| Vector | `D3S2_M26_MID_FOCUS_ITER_NEXT_PORT_FAILURE_NOTE0` |
| Fault | spy `iter_next` / `IO_ERROR` with **`fault.used`** |
| Raw Port shape | third `ITER_OPEN` OK → first mid-FOCUS `ITER_NEXT` OK → faulted `ITER_NEXT` `IO_ERROR` |
| Checkpoint | mid-FOCUS real comparison（phase / PASS_INTERNAL / FOCUS_LIVE / incomplete masks / last_carrier / open=3 / begin=1） |
| H3 observable proof | sticky **`STORAGE`** + phase **`FAILED`** + incomplete masks + no observable fabricated undercount/orphan **`CORRUPT` outcome/path**（production note invocation count は測定しない） |
| `note_count=0` | **reference model only**（JSON formal）。production `note_count` call counter は **claim しない** |
| Complement | P0-C `D3S2_M25_BIND_EXACT_GET_PORT_FAILURE_NOTE0`（BIND exact_get Port） |

### Major evidence paths

| path | role |
| --- | --- |
| `src/runtime/domain_store_d3s2.c` / `.h` | production multipass evaluator |
| `src/runtime/domain_store_scanner.c` | `begin_profiled_d3s2` private seam |
| `tests/runtime/domain_store_d3s2_test.c` | unit acceptance |
| `tools/domain_scan_crossrow_d3s2_vector_gen.py` | independent generator |
| `spec/vectors/domain-scan-crossrow-v1.json` | append-only authority |
| `tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` | production bridge |
| `tools/domain_scan_dsd1_composition_vector_gen.py` | DSD1 generator |
| `spec/vectors/domain-scan-dsd1-composition-v1.json` | DSD1 7-session composition |
| `docs/17-foundation-domain-store.md` §18.13 / §18.2 / §18.13.19 | Normative freeze + current status |

## Acceptance boundary

| Accepted | Not accepted / pending |
| --- | --- |
| D3-S2 declared multi-count implementation complete | D3-S3 / D3-S4 implementation |
| modes 21..26 six self-contained sessions + same-txn multipass | D3-S5..S12 |
| crossrow d3s2 authority 144 + independent generator/bridge | D3 overall complete |
| DSD1 7-session composition sibling | Stage 5 D3 bind / Stage 5 complete |
| private surface / context 306/320 / mutation 0 | `storage_recovery_complete=1` |
| §18.13.15 cases 1..21 closed on fixed candidate | D4 / public Runtime |
| Sol P1-E GO + Grok full 21-case verdict A | ESP-IDF hardware / USB / LoRa HIL |
| Official CI + local Release/ASan green | SDK / field / V1 readiness |
| | production `note_count` call counter |

## Historical freezes preserved

次は **一字も書き換えない** historical 記録である:

- §18.13.18 After D3-S2a docs freeze の NO 表と警告
- §18.12.9 After D3-S1 implementation の当時 S2 pending 表
- §18.14.18 S3a historical 表
- D3-S0 / S1a / S2a / S3a / S4a freeze 本文

## Verdict

**D3-S2 declared multi-count implementation Accepted on fixed candidate `39e4752` / merge `ca02e24` / PR #105.**  
Sol high P1-E re-review **P0=P1=P2=0 GO**。Grok high full 21-case fixed-candidate audit **verdict A**。  
Sol high status-delta initial review **P0=0/P1=0/P2=2 NO-GO** の文書P2 2件は修正され、closure re-review **P0=P1=P2=0 GO**。  
本 Accepted は **D3-S2 slice only** を対象とし、D3 overall、Stage 5 D3 bind、D4、public Runtime、ESP/hardware HIL、SDK/V1 readiness の完成を意味しない。compile/link ≠ HIL。production `note_count` counter は非 claim。
