# D3-S2 Completion Audit (non-normative)

状態: **NOT COMPLETE**<br>
種別: evidence-based completion audit（非規範 review record）<br>
監査日: 2026-07-12<br>
対象: `Aero123421/Ninlil-Runtime`

## Audit boundary / fixed commit

| Item | Value |
| --- | --- |
| Fixed commit | `8205afc721a46655a021aa81a003f09c2649fa48` |
| Branch tip message | `Mode21クロス行oracleを追加 (#57)` |
| `origin/main` SHA | matches fixed commit above |
| Normative basis | `docs/17-foundation-domain-store.md` **§18.13**（特に **§18.13.15** case classes 1..21、**§18.13.16** DSD1、**§18.13.17** exclusions、**§18.13.18** completion boundary） |
| Production | `src/runtime/domain_store_d3s2.c` / `.h`、scanner 接続 `src/runtime/domain_store_scanner.c` |
| Unit tests | `tests/runtime/domain_store_d3s2_test.c` |
| Formal oracle | `tools/domain_scan_crossrow_d3s2_vector_gen.py`、`spec/vectors/domain-scan-crossrow-v1.json`（format `ninlil-domain-scan-crossrow-v1-d3s2`）、`tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` |
| Semantic oracle（supplemental; §18.13.15 formal sibling ではない） | `tools/domain_scan_d3s2_semantic_oracle.py`、`spec/vectors/domain-scan-declared-multicount-semantics-v1.json`、`tests/runtime/domain_store_d3s2_semantic_oracle_bridge_test.c` |
| Composition artifact（D2-S5; S2 DSD1 ではない） | `spec/vectors/domain-scan-composition-v1.json` format `ninlil-domain-scan-composition-v1-d2s5` |

### Audit method / false-completion guards

本 record は **実装完了宣言ではなく**、固定 commit 上の実物を §18.13.15 の 21 case classes と §18.13.18 boundary に対して証拠ベースで判定する。

Closed status taxonomy（各 case 1 つだけ）:

| Status | Meaning used here |
| --- | --- |
| `FORMAL_ORACLE_AND_PRODUCTION_BRIDGE` | append-only crossrow d3s2 vector ID(s) + production bridge execution path exists for the case core |
| `UNIT_ONLY` | unit / semantic-only evidence; **not** formal crossrow sibling |
| `PARTIAL` | some real evidence, but core sub-claims of the case remain unproved |
| `MISSING` | no formal vector and no unit/semantic production evidence that closes the case |
| `OUT_OF_SCOPE` | Normative explicitly assigns ownership to another stage（本 audit では 21 cases に該当なし） |

**False-completion guards（必須）:**

1. formal oracle に無い `UNIT_ONLY` を完成扱いしない。
2. production symbol / phase machine が存在するだけでも完成扱いしない。
3. semantic oracle（31 abstract close cases）は formal sibling の代替にしない。
4. ESP-IDF / USB / LoRa / public Runtime / Stage5 D3 bind / D3 overall complete は claim しない。
5. 証拠が欠ける case が 1 つでもあれば overall verdict は **NOT COMPLETE**。

### Executed evidence (read-only)

| Command / binary | Result |
| --- | --- |
| `python3 tools/domain_scan_crossrow_d3s2_vector_gen.py check spec/vectors/domain-scan-crossrow-v1.json` | ok; `vectors=112` (`d3s1_prefix=94`, `d3s2_suffix=18`); `content_sha256=519bc7465b47bc6da957e8815c112da6445a811c5fcb5b65ff9c3cd3038bff79` |
| `python3 tools/domain_scan_d3s2_semantic_oracle.py check ...declared-multicount-semantics-v1.json` | ok; 31 vectors |
| generator / semantic `self-test` | ok |
| `./build-debug/ninlil_domain_store_d3s2_test` | exit 0 |
| `./build-debug/ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test` | exit 0; pins `NINLIL_D3S1_VECTOR_COUNT==94`, `NINLIL_D3S2_VECTOR_COUNT==18` |
| `./build-debug/ninlil_domain_store_d3s2_semantic_oracle_bridge_test` | exit 0; 14 bridged semantic IDs |

### Formal d3s2 suffix inventory (18 vectors)

| # | Vector ID | Mode | Kind | Role |
| ---: | --- | ---: | --- | --- |
| 0 | `D3S2_M21_EMPTY_CARRIER_EMPTY_SECONDARY` | 21 | `mode21_empty_carrier_empty_secondary_ok` | empty smoke |
| 1 | `D3S2_M22_EMPTY_CARRIER_EMPTY_SECONDARY` | 22 | `mode22_empty_carrier_empty_secondary_ok` | empty smoke |
| 2 | `D3S2_M23_EMPTY_CARRIER_EMPTY_SECONDARY` | 23 | `mode23_empty_carrier_empty_secondary_ok` | empty smoke |
| 3 | `D3S2_M24_EMPTY_CARRIER_EMPTY_SECONDARY` | 24 | `mode24_empty_carrier_empty_secondary_ok` | empty smoke |
| 4 | `D3S2_M25_EMPTY_CARRIER_EMPTY_SECONDARY` | 25 | `mode25_empty_carrier_empty_secondary_ok` | empty smoke |
| 5 | `D3S2_M26_EMPTY_CARRIER_EMPTY_SECONDARY` | 26 | `mode26_empty_carrier_empty_secondary_ok` | empty smoke |
| 6 | `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK` | 25 | `mode25_cum_total1_recent_slot1_anchor_ok` | positive |
| 7 | `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT` | 25 | `mode25_recent_without_cum_carrier_absent_corrupt` | corruption |
| 8 | `D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK` | 26 | `mode26_es_resume1_mgmt_resume_anchor_ok` | positive |
| 9 | `D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT` | 26 | `mode26_mgmt_without_es_carrier_absent_corrupt` | corruption |
| 10 | `D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK` | 24 | `mode24_rc_reply1_receipt_delivery_ok` | positive |
| 11 | `D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT` | 24 | `mode24_rr_without_rc_carrier_absent_corrupt` | corruption |
| 12 | `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK` | 23 | `mode23_tx_state_slots_L_equation_anchor_ok` | positive |
| 13 | `D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT` | 23 | `mode23_evidence_without_state_carrier_absent_corrupt` | corruption |
| 14 | `D3S2_M22_RC_APP1_ATT_DLV_OK` | 22 | `mode22_rc_app1_dlv_attempt_delivery_ok` | positive |
| 15 | `D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT` | 22 | `mode22_att_without_rc_carrier_absent_corrupt` | corruption |
| 16 | `D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK` | 21 | `mode21_state_cum1_att_tx_aii_anchor_ok` | positive |
| 17 | `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT` | 21 | `mode21_att_without_aii_index_pair_absent_corrupt` | corruption |

All 18 are one mode / one `begin_profiled_d3s2` / one RO txn. Bridge asserts `spy.begin_calls == 1u` and full Port-trace equality.

## Verdict

# **NOT COMPLETE**

理由（要約）:

- formal sibling は 94 d3s1 prefix + **18** d3s2 suffix まで append 済みで、**modes 21..26 の empty / 1-carrier positive / 1-class corruption** は揃う。
- しかし §18.13.15 の anti-false-pass 集合のうち、**multi-owner SHA interleave、budget mid-focus resume、DSD1 multi-session composition、two-txn harness fail、Mode22 unexpected INDEX、Port mid-FOCUS/BIND note 0、profile-mismatch evaluator-off、get-budget 横断 gate** 等が formal または production bridge として未閉。
- production / unit / semantic は広いが、false-completion guard により formal 欠落は完成に昇格しない。

### Status counts (21 case classes)

| Status | Count | Case #s |
| --- | ---: | --- |
| `FORMAL_ORACLE_AND_PRODUCTION_BRIDGE` | **4** | 1, 9, 16, 18 |
| `UNIT_ONLY` | **0** | — |
| `PARTIAL` | **14** | 3, 4, 5, 6, 7, 8, 10, 11, 12, 14, 15, 19, 20, 21 |
| `MISSING` | **3** | 2, 13, 17 |
| `OUT_OF_SCOPE` | **0** | — |

## §18.13.15 case classes 1..21

| # | Case class (Normative) | Status | Evidence / gap |
| ---: | --- | --- | --- |
| 1 | Modes 21–26 positive ordinary counts（plan ABSENT）— one mode per session | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal positives: `D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK`, `D3S2_M22_RC_APP1_ATT_DLV_OK`, `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK`, `D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK`, `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK`, `D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK`. Bridge: `domain_store_scanner_crossrow_d3s2_oracle_bridge_test` / `run_vector`. Production: `ninlil_domain_scan_begin_profiled_d3s2`, `ninlil_domain_scan_d3s2_drive`. **Residual richness gap**（multi-count A/B/C >1, cancel lanes）は formal 最小 1-row のみだが case core は formal。 |
| 2 | SHA non-contiguous multi-owner interleave（same subtype band, different owners） | **MISSING** | No formal vector with ≥2 owners interleaved under SHA256_COMPOSITE in one subtype band. No unit fixture with two TX/DELIVERY owners and assert both carriers selected in complete-key order. Production has `last_carrier_key` / `last_carrier_key_len` and SELECT skip (`domain_store_d3s2.c` carrier frontier) — **code alone is not completion**. |
| 3 | Known-slot evidence/reply/retry presence matrix + illegal slot/kind | **PARTIAL** | Formal matrix **success**: Mode23/24/25 positive vectors above. Unit illegal / missing: `test_d3s2_p0_8_mode23_slot_presence_required`, `test_d3s2_p0_7_mode24_declared_missing_reply_fail`. Semantic abstract: `mode23_slot_missing`, `mode23_late_bound_fail`, `mode24_popcount_mismatch`. **Gap:** formal has **no** illegal-slot / illegal-kind / missing-slot corrupt vectors. |
| 4 | Stream attempt/index/management under/over count | **PARTIAL** | Unit stream under/over-ish: `test_d3s2_p0_2_no_select_residual_double_count`（observed_a=1 vs declared 0 → CORRUPT）, `test_d3s2_mode26_management_count_mismatch`. Semantic: `mode21_index_mismatch`, `mode26_management_mismatch`. **Gap:** formal positives only; no formal undercount/overcount stream fail for Mode21 A/B/C or Mode22/26 ordinary path. Mode21 pair-absent uses CLEANUP_PLAN so ordinary INDEX undercount is **skipped**, not proved. |
| 5 | CLEANUP_PLAN PRESENT → Mode21/22 ordinary skip; 23–26 still ordinary | **PARTIAL** | Formal Mode21 constructible skip path: `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT`（notes: CLEANUP_PLAN PRESENT / cleanup_skip so INDEX undercount does not preempt BIND）. Unit: `test_d3s2_p0_5_cleanup_plan_true_primary_skip` asserts `context.cleanup_skip == 1`. Semantic: `mode21_cleanup_skip_ok`, `mode22_cleanup_still_binds`. Production: `apply_cleanup_plan_gate`. **Gap:** Mode22 cleanup formal vector absent; Modes 23–26 “plan PRESENT still ordinary” formal anti-skip absent. |
| 6 | Carrier cursor no-skip / no-dup; last_carrier_key frontier; mode-dependent carrier set | **PARTIAL** | Production: install updates `last_carrier_key` / len; SELECT compares complete key. Unit residual defense: `test_d3s2_p0_2_no_select_residual_double_count`（SELECT residual must not count）. Formal vectors are **single-carrier** only. **Gap:** no multi-carrier formal/unit that proves every eligible carrier selected exactly once under complete-key order（no-skip/no-dup）. |
| 7 | Same-txn multipass Port trace; two-txn harness fail | **PARTIAL** | Formal: every d3s2 vector Port trace is one `begin:READ_ONLY` + multiple sequential `iter_open:prefix0`; bridge requires `begin_calls == 1` and exact trace. Unit same-txn: `test_d3s2_baseline_reopen_pass_internal_freeze`（`begin_calls==1`, reopen, freeze counters）. **Gap:** **no** harness/vector that **fails** a two-txn list-then-count pattern（§18.13.15 “two-txn harness fail” is architecture requirement, not yet an anti-pass artifact）. |
| 8 | BIND missing true primary / PVD mismatch / raw mismatch / Mode21 pair fail / Mode22 unexpected INDEX | **PARTIAL** | Formal Mode21 pair ABSENT: `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT`. Unit primary PVD: `test_d3s2_p1_mode21_bind_primary_pvd_mismatch`; pair: `test_d3s2_p1_mode21_bind_index_pair_absent`. Production Mode22 unexpected INDEX PRESENT → `note_finding` in BIND_ATTEMPT pair probe (`domain_store_d3s2.c`). **Gap:** Mode22 unexpected INDEX has **no** formal vector and **no** unit test; raw mismatch dedicated path sparse; true-primary ABSENT formal sparse. |
| 9 | BIND missing declared-count carrier / wrong carrier body subject（orphan） | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal carrier-ABSENT orphans: `D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT`, `D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT`, `D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT`, `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT`, `D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT`. Mode21 unit: `test_d3s2_p1_mode21_bind_carrier_absent`（also semantic bridge `empty_carrier_orphan_fail`）. Production: BIND step2 companion ABSENT → `note_terminal_corrupt`. |
| 10 | Count green without that mode’s BIND set → must not pass | **PARTIAL** | Production COMPLETE requires `binding_complete_mask` full for `focus_mode` (`domain_store_d3s2.c` BIND close). Unit incomplete session: `test_d3s2_incomplete_finalize_reject_then_abort`. Semantic abstract: `bind_primary_or_carrier_fail` / `mode22_cleanup_still_binds`（not wire formal）. **Gap:** no formal vector that achieves focus count green then omits BIND and still expects COMPLETE（anti-pass）. |
| 11 | Port terminal mid-FOCUS/BIND（incl. carrier/primary/pair gets）→ note 0 | **PARTIAL** | Unit: `test_d3s2_port_failure_no_note` injects `NINLIL_SPY_OP_ITER_NEXT` fault → sticky `NINLIL_E_STORAGE`, phase FAILED. Semantic bridge asserts fixture `note_count==0` for id `port_failure_no_note`. Production H3 comments: Port → note 0. **Gap:** fault is early iter_next（not mid-FOCUS/BIND carrier/primary/pair **get**）；unit does **not** assert result/session note count 0; formal crossrow has **no** Port-terminal vector and **no** `note_count` field. |
| 12 | Profile mismatch / future candidate → S2 evaluator 0; INTERNAL must not clear baseline flags | **PARTIAL** | Unit freeze（flags already 0, prove not mutated under INTERNAL）: `test_d3s2_baseline_reopen_pass_internal_freeze` snapshots `profile_mismatch` / `future_profile_candidate` / `recognizable_future_seen` before/after. Production: `ninlil_domain_scan_d3s2_on_row` returns early when `profile_exact_active==0` or mismatch/future set. Formal vectors all ship `profile_mismatch=0` / `future_profile_candidate=0`. **Gap:** no S2 formal/unit that **sets** mismatch or future and proves evaluator notes 0 / no S2 corrupt under INTERNAL. |
| 13 | Budget mid-focus resume（same session B5, not restart B11） | **MISSING** | Unit only B0: `test_d3s2_drive_budget_zero`（`row_budget==0` → INVALID_ARGUMENT）. Composition oracle `S5_BUDGET_1_PARTIAL_RESUME` is **D2-S5**, not S2 mid-focus. **No** unit/formal that stops mid-FOCUS with budget exhaustion, preserves `focus_live` / observed / `last_carrier_key`, and resumes same session. |
| 14 | Empty secondary vs declared>0; empty-carrier still BIND; empty-carrier + non-empty secondary fails via BIND | **PARTIAL** | Formal empty-carrier empty-secondary COMPLETE ×6（IDs above）+ empty-carrier + secondary orphan fails（case 9 vectors）. Unit empty success: `test_d3s2_empty_carrier_empty_secondary_success`. **Gap:** formal “carrier present, declared>0, secondary empty → ordinary undercount CORRUPT” not covered（Mode24 zero-reply is declared=0 success path）. |
| 15 | Mode22 INDEX expect 0 via BIND_ATTEMPT ABSENT only; unexpected index; Mode21 BIND_INDEX no STATE companion | **PARTIAL** | Formal Mode22 success Port/model path includes INDEX ABSENT peer (`D3S2_M22_RC_APP1_ATT_DLV_OK`, `d3_peer_get_count=5`). Production Mode22 PRESENT → note; Mode21 `bind_index_row` comment/code “No STATE companion”. Formal Mode21 success notes get budget INDEX≤2. **Gap:** unexpected INDEX PRESENT formal/unit absent; BIND_INDEX no-STATE is production+notes, not an independent anti-get oracle assert. |
| 16 | Mode25 RECENT-without-CUM → BIND_RETRY carrier fail; CUM self-carrier primary-only | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT`（STORAGE_CORRUPT, peer_get=1）+ success `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK`（CUM self-carrier + RECENT companion path; generator documents primary-only for CUM）. Unit: `test_d3s2_mode25_recent_without_cumulative_fail`. Bridge runs both. |
| 17 | DSD1 composition fixtures（multi-session S1+S2; not Mode 28; not dual-bound） | **MISSING** | §18.13.16: composition only, multi-session chain. `domain-scan-composition-v1.json` is **D2-S5** (`format=ninlil-domain-scan-composition-v1-d2s5`, 22 vectors, no Mode22/23/24 S2 chain). No harness that sequences `begin_profiled_d3s1` sessions + `begin_profiled_d3s2` sessions on one DSD1 fixture with DONE between. Dual-bound forbidden is code-enforced in scanner begin, not DSD1 product proof. |
| 18 | exact 94 d3s1 prefix retained after append | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Artifact: `d3s1_prefix_count=94`, prefix authority pins, append-only generator `check`. Bridge: `REQUIRE(NINLIL_D3S1_VECTOR_COUNT == 94u)`. CMake: `domain_scan_crossrow_vector_oracle`, fixture freshness asserts `NINLIL_D3S1_VECTOR_COUNT ((size_t)94u)`. |
| 19 | Mode23 `valid = M + overflow` equation + late coherence without false late equality | **PARTIAL** | Formal success equation path: `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK`. Semantic equation/late abstracts: `mode23_slots_equation_ok`, `mode23_late_bound_fail`（not full formal wire）. Unit nonempty success: `test_d3s2_mode23_nonempty_success`. **Gap:** formal lacks equation-fail and late-coherence-fail vectors; late non-equality law under-proved on production bridge. |
| 20 | Six-session product: harness must not assume one baseline covers six modes | **PARTIAL** | Formal structure: six independent empty smokes（modes 21..26）each with own begin; bridge asserts one mode per vector and `begin_calls==1`. Product cost honesty is structural. **Gap:** no anti-pass that a single session/mode claims all six; no multi-mode orchestration forbidden vector. |
| 21 | Get-budget freeze: BIND ≤1 primary + ≤1 carrier + ≤1 pair（max 3 ATTEMPT） | **PARTIAL** | Formal expected field `d3_peer_get_count` exists（e.g. Mode21 success 7, Mode22 success 5, Mode21 pair-absent 5）. Generator notes “Get budget ATTEMPT≤3 INDEX≤2”. **Gap:** `domain_store_scanner_crossrow_d3s2_oracle_bridge_test` does **not** compare `d3_peer_get_count`（unlike d3s1 bridge）. No cross-vector gate that per-secondary-row gets ≤3 / fails unbounded gets. Session totals alone do not freeze per-row budget. |

### Special-focus answers (audit request)

| Focus | Finding |
| --- | --- |
| SHA non-contiguous multi-owner interleave in formal oracle? | **No.** Suffix 18 has no multi-owner interleaved SHA256_COMPOSITE case. |
| two-txn harness fail exists? | **No.** Same-txn multipass is proved; two-txn anti-pass artifact absent. |
| Port terminal mid-FOCUS/BIND note 0? | **Not to note 0.** Early Port fail unit exists; mid-FOCUS/BIND get path + note_count assert missing. |
| budget mid-focus same-session resume formal or unit-only? | **Neither.** Missing. Only budget 0 unit. |
| profile mismatch / future flags freeze | Unit proves **non-mutation under INTERNAL** when already clear; mismatch/future → evaluator-off path not exercised for S2. |
| carrier cursor multiple carriers no-skip/no-dup | Production cursor exists; multi-carrier proof **missing**. |
| Mode22 unexpected INDEX | Production branch only; formal/unit **missing**. |
| DSD1 multi-session composition（not Mode28） | **Missing.** Composition artifact is D2-S5. |
| six-session product not one baseline | Structural empty smokes support honesty; no anti-pass. |
| get budget freeze formal-only vs cross gate | Field in JSON; **not** d3s2-bridge-compared; no per-row cross gate. |

## Six modes 21..26 inventory

| Mode | Empty smoke | Positive success | Corruption case |
| ---: | --- | --- | --- |
| **21** | `D3S2_M21_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK`（cum=1, ATT+AII+ANCHOR） | `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT`（CLEANUP_PLAN PRESENT → INDEX pair ABSENT） |
| **22** | `D3S2_M22_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M22_RC_APP1_ATT_DLV_OK`（RC app=1, DLV ATT, DELIVERY） | `D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT` |
| **23** | `D3S2_M23_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK`（slots 0..L equation） | `D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT` |
| **24** | `D3S2_M24_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK` | `D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT` |
| **25** | `D3S2_M25_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK` | `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT` |
| **26** | `D3S2_M26_EMPTY_CARRIER_EMPTY_SECONDARY` | `D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK` | `D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT` |

Inventory completeness note: every mode has the three **classes**, but each class is still a **thin** slice relative to §18.13.15 exhaustive anti-false-pass list（see PARTIAL/MISSING table）.

### Unit / semantic supplement (not formal completion)

Representative unit functions (`domain_store_d3s2_test.c` / `ninlil_d3s2_run_all_tests`):

- layout/masks: `test_d3s2_context_size_session_and_masks`
- begin/prevalidation: `test_d3s2_begin_prevalidation`, `test_d3s2_valid_begin_txn_iter_context`
- PASS_INTERNAL freeze: `test_d3s2_baseline_reopen_pass_internal_freeze`
- Mode21/22 declared lanes / cleanup / BIND filters: `test_d3s2_p0_3_*` … `p0_6_*`, `p1_mode21_bind_*`
- Mode23–26 successes and selected fails: `test_d3s2_mode23_*`, `mode24_*`, `mode25_*`, `mode26_*`
- empty / port: `test_d3s2_empty_carrier_empty_secondary_success`, `test_d3s2_port_failure_no_note`

Semantic oracle: 31 abstract cases; production bridge covers **14** IDs only（bridge header comment: not full formal completion）.

## §18.13.18 completion boundary claims (current status)

| Claim | After S2a docs freeze (Normative text) | On fixed commit (audit) |
| --- | --- | --- |
| D3-S0 architecture freeze | yes | **yes**（docs historical; unchanged by this audit） |
| D3-S1a Normative freeze | yes | **yes** |
| D3-S1 implementation complete | yes | **yes**（prior; 94-vector prefix retained） |
| D3-S2a Normative freeze | yes | **yes**（§18.13 docs freeze text remains; not rewritten to “impl complete”） |
| D3-S2 implementation complete | **no** | **still no**（six mode sessions + code/oracle incomplete vs 21 case classes） |
| Crossrow d3s2 JSON / generator / bridge | no（architecture only at S2a） | **partially present**（18 suffix vectors + generator + production bridge; **not** exhaustive 21-case complete） |
| D3 complete / S12 | no | **no** |
| Stage 5 complete / `storage_recovery_complete=1` | no | **no** |
| Stage5 allocates/binds/runs D3 context | no until S12 | **no**（Stage5 seam still not D3-bound; private S2 begin is test/private path） |
| public Runtime / D4 / ESP-IDF / hardware | no | **no / not claimed** |
| Implemented private APIs/types/constants exist | no claim at S2a | **exist on this commit** as private implementation（`ninlil_domain_scan_begin_profiled_d3s2`, context 306/320, etc.）— existence ≠ S2 complete |

S2a historical row を “implementation complete” へ書き換えてはならない、という §18.13.18 警告は本 audit でも維持する。

## CMake / CI gates (observed)

Present on fixed commit（`CMakeLists.txt`）:

- `domain_store_d3s2` unit executable/test
- d3s2 wire fixture generate / source / self-test / freshness
- `domain_scan_crossrow_vector_oracle` + self-test + fixture freshness（pins d3s1=94, d3s2=18）
- `domain_store_scanner_crossrow_oracle_bridge`（d3s1 prefix）
- `domain_store_scanner_crossrow_d3s2_oracle_bridge`（d3s2 suffix）
- `domain_scan_d3s2_semantic_oracle` + self-test + semantic bridge

These gates make current suffix **regression-safe**; they do **not** encode full §18.13.15 case-class coverage.

## Remaining work (P0 / P1 / P2) — minimal next PR slices

### P0 — anti-false-pass formal slices（blocking complete）

#### Slice P0-A: Multi-owner SHA interleave + carrier cursor
- **Cases:** 2, 6
- **Work:** append formal vectors with ≥2 owners / multiple carriers in one subtype band; assert each selected once in complete-key order; no skip/dup; mode-dependent carrier sets.
- **Acceptance:** new vector IDs in crossrow d3s2 suffix; generator independent expected; production bridge green; unit optional only as secondary.

#### Slice P0-B: Budget mid-focus resume (B5)
- **Cases:** 13
- **Work:** same-session drive with small `row_budget` mid-FOCUS stream or mid known-slot matrix; assert focus_live/observed/last_carrier_key preserved; resume continues; distinguish B11 restart.
- **Acceptance:** formal call sequence with partial budgets + bridge compare of phase/masks/observed; unit alone insufficient for complete.

#### Slice P0-C: Port mid-FOCUS/BIND note 0 + two-txn fail
- **Cases:** 7 (remaining), 11
- **Work:** (1) Port fault on BIND exact_get / mid-FOCUS iter_next with assert **note_count=0** and no fabricated undercount/orphan; (2) harness that uses two txns for list-then-count **must fail** closed.
- **Acceptance:** formal vector(s) or oracle self-test anti-pass + production bridge; sticky Port without CORRUPT note path.

#### Slice P0-D: Mode22 unexpected INDEX + BIND primary/raw formal
- **Cases:** 8, 15
- **Work:** Mode22 ATTEMPT with unexpected ATTEMPT_ID_INDEX PRESENT → STORAGE_CORRUPT via BIND_ATTEMPT ABSENT-peer fail; add true-primary ABSENT/PVD/raw formal where unit-only today.
- **Acceptance:** formal IDs + bridge; Mode21 BIND_INDEX no-STATE companion get-count pin bridged.

### P1 — completeness of ordinary / cleanup / stream / known-slot fails

#### Slice P1-A: Stream under/over + cleanup matrix
- **Cases:** 4, 5, 14 (remaining)
- **Work:** formal Mode21 A/B/C under/over; Mode22 app/cancel under/over; Mode26 overcount; Mode21/22 CLEANUP skip without false note; Modes 23–26 plan PRESENT still ordinary; declared>0 empty secondary.

#### Slice P1-B: Known-slot illegal + Mode23 equation/late fails
- **Cases:** 3, 19
- **Work:** illegal slot/kind formal; Mode23 equation fail; late coherence fail without requiring false late equality.

#### Slice P1-C: Count-without-BIND anti-pass + profile/future evaluator-off
- **Cases:** 10, 12
- **Work:** fixture where counts would pass but BIND incomplete → not COMPLETE; profile_mismatch/future candidate fixture with S2 notes 0 and frozen flags.

#### Slice P1-D: Get-budget cross gate
- **Cases:** 21
- **Work:** bridge compares `d3_peer_get_count`; generator self-test enforces per-row max 3 / Mode21 INDEX ≤2; optional unbounded-get anti-pass.

### P2 — composition / product honesty

#### Slice P2-A: DSD1 multi-session composition
- **Cases:** 17
- **Work:** multi-session harness vectors chaining S1 modes 11/14/17/19 + S2 modes 22/23/24 on one fixture; cleanup DONE between sessions; never dual-bound. **Not** Mode 28.

#### Slice P2-B: Six-session product anti-pass documentation gate
- **Cases:** 20（residual）
- **Work:** generator/bridge assert no vector mode field lists multiple modes; reject one-session multi-mode expected COMPLETE for 21..26 product.

#### Slice P2-C: Promote remaining UNIT/semantic-only paths into formal when needed
- After P0/P1, re-run this audit template; only then consider D3-S2 implementation complete claim in a **separate** change set（do not rewrite S2a historical freeze text）.

## Non-claims (explicit)

This audit does **not** claim:

- D3-S2 implementation complete
- D3 complete / S3–S12 complete
- Stage 5 complete / Stage5 D3 bind
- public Runtime / D4 writer E2E
- ESP-IDF / USB / LoRa / hardware
- semantic oracle 31/31 wire realization
- that production code existence implies oracle completeness

## Artifact map (read at audit time)

| Path | Role |
| --- | --- |
| `docs/17-foundation-domain-store.md` §18.13 | Normative contract |
| `spec/vectors/domain-scan-crossrow-v1.json` | Formal sibling（112 = 94+18） |
| `tools/domain_scan_crossrow_d3s2_vector_gen.py` | Independent generator / pins |
| `tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` | Production formal bridge |
| `src/runtime/domain_store_d3s2.c` / `.h` | S2 phase machine |
| `src/runtime/domain_store_scanner.c` | begin/drive/H1/H2 integration |
| `tests/runtime/domain_store_d3s2_test.c` | Unit regressions |
| `tools/domain_scan_d3s2_semantic_oracle.py` | Supplemental close semantics |
| `spec/vectors/domain-scan-composition-v1.json` | D2-S5 composition only |

## Change control

- This file is **non-normative**.
- Audit edited only review records; Normative docs / production / tests / tools / vectors / CMake were **not** modified for this audit.
- No commit/push performed by the auditor as part of creating this record.
