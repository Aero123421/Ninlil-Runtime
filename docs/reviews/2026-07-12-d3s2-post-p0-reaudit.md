# D3-S2 Post-P0 Re-Audit (non-normative)

状態: **NOT COMPLETE**（D3-S2 implementation complete は claim しない）
種別: evidence-based post-P0 re-audit（非規範 review record）
監査日: 2026-07-12
監査者モデル: Grok 4.5 high
対象 worktree: `/Users/dt/job/LoRa/ninlil-grok-d3s2-core`
branch: `codex/d3s2-reaudit`
対象: `Aero123421/Ninlil-Runtime` Domain Store D3-S2

本 record は **監査だけ** を行う。不足機能を完成扱いしない。Normative / production / tests / tools / vectors / 既存 review は **変更しない**。本ファイルのみ新規作成。

---

## 1. Audit boundary / fixed commit

| Item | Value |
| --- | --- |
| Fixed commit | `fec9edba193e2ade6c24a3062001ffb036baba90` |
| Tip message | `BIND参照不整合oracleを追加 (#62)` |
| Base pin | `origin/main` at the same SHA（this worktree HEAD） |
| Prior audit | `docs/reviews/2026-07-12-d3s2-completion-audit.md` @ `8205afc`（94+18=112; P0 open） |
| Normative basis | `docs/17-foundation-domain-store.md` **§18.13** 全体、特に **§18.13.15** minimum cases **1..21**、**§18.13.16** DSD1、**§18.13.17** exclusions、**§18.13.18** completion boundary |
| Quality baseline | `docs/07-testing-and-quality.md`（test layers / Foundation conformance / portable→ESP-IDF ladder; D3-S2 固有 vector 表は持たない） |
| Production | `src/runtime/domain_store_d3s2.c` / `.h`、`src/runtime/domain_store_scanner.c`（`ninlil_domain_scan_begin_profiled_d3s2`） |
| Unit | `tests/runtime/domain_store_d3s2_test.c` |
| Formal sibling | `tools/domain_scan_crossrow_d3s2_vector_gen.py`、`spec/vectors/domain-scan-crossrow-v1.json` format `ninlil-domain-scan-crossrow-v1-d3s2`、`tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` |
| Semantic（supplemental; formal sibling ではない） | `tools/domain_scan_d3s2_semantic_oracle.py`、`spec/vectors/domain-scan-declared-multicount-semantics-v1.json`、`tests/runtime/domain_store_d3s2_semantic_oracle_bridge_test.c` |
| Composition（D2-S5; S2 DSD1 ではない） | `spec/vectors/domain-scan-composition-v1.json` format `ninlil-domain-scan-composition-v1-d2s5` |

### Status taxonomy（closed; 各 case 1 つ）

| Status | Meaning used here |
| --- | --- |
| `FORMAL_ORACLE_AND_PRODUCTION_BRIDGE` | append-only crossrow d3s2 vector ID(s) + production bridge execution path covers the case core |
| `PRODUCTION_AND_UNIT_ONLY` | production path + unit (and/or semantic) evidence only; **no** formal crossrow sibling for the case core |
| `PARTIAL` | real evidence exists, but one or more Normative sub-claims remain unproved |
| `MISSING` | no formal vector and no production/unit evidence that closes the case core |
| `UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS` | case (or named sub-claim) cannot be constructed under D1 same-record validation + same `READ_ONLY` snapshot without violating prior Normative; **not** “unimplemented” |

**False-completion guards:**

1. formal に無い unit/semantic を完成扱いしない。
2. production symbol / phase machine 存在だけでは完成扱いしない。
3. semantic oracle は formal sibling の代替にしない。
4. `note_count=0` は JSON formal reference のみ; production call counter 未実測境界を維持する。
5. ESP-IDF / public Runtime / Stage5 D3 bind / D3 overall complete は claim しない。
6. 21 case のいずれかが `PARTIAL` / `MISSING` / `PRODUCTION_AND_UNIT_ONLY` なら overall **NOT COMPLETE**。
7. `UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS` は「未実装」と混同しない; 代替 formal がある場合は代替を明記する。

---

## 2. Evidence commands (executed read-only)

| Command | Result |
| --- | --- |
| `git rev-parse HEAD` | `fec9edba193e2ade6c24a3062001ffb036baba90` |
| `python3 tools/domain_scan_crossrow_d3s2_vector_gen.py check spec/vectors/domain-scan-crossrow-v1.json` | **ok**; `vectors=119` (`d3s1_prefix=94`, `d3s2_suffix=25`); `content_sha256=63ed46d9ba467e95ed53781f096d581fa42234e0e41cbb7022ffb1df23eeeb40` |
| `python3 tools/domain_scan_crossrow_d3s2_vector_gen.py self-test` | **ok**（prefix freezes + slice pins + **two-txn anti-pass** + forbidden ops + clean pass） |
| Mechanical JSON extract | 25 suffix IDs / `final_status` / `d3_peer_get_count` / optional `note_count`（下表） |
| `rg` existence of formal IDs, unit names, production symbols | all cited symbols present（see §8） |

**Not executed in this audit session (binaries may exist under `build-*` but were not re-run as gate):** production C unit/bridge binaries. Formal check + generator self-test + static code/test/vector identity are the evidence base. Bridge source **does** assert `NINLIL_D3S2_VECTOR_COUNT == 25u` and compares **`d3_peer_get_count`** on every suffix vector.

### Inventory / content hash

| Metric | Value |
| --- | ---: |
| Total vectors | **119** |
| d3s1 prefix | **94** |
| d3s2 suffix | **25** |
| Decomposition | **119 = 94 + 25** |
| Format | `ninlil-domain-scan-crossrow-v1-d3s2` |
| `content_sha256` | `63ed46d9ba467e95ed53781f096d581fa42234e0e41cbb7022ffb1df23eeeb40` |
| Prior freeze (old audit) | 112 = 94+18; `content_sha256=519bc7465b47bc6da957e8815c112da6445a811c5fcb5b65ff9c3cd3038bff79` |
| 115-prefix authority (pre-P0-D) | `content_sha256=605a77d256e5bcadddba5a5973ab2d59d86687d5988a5e686d6e4a093dcd8059` |

Suffix growth since prior audit: **+7** formal vectors（P0-A 1 + P0-B 1 + P0-C 1 + P0-D 4）。

---

## 3. Formal d3s2 suffix inventory (25)

| # | Vector ID | Mode | Kind | `final_status` | `d3_peer_get_count` | `note_count` | Slice |
| ---: | --- | ---: | --- | --- | ---: | --- | --- |
| 0 | `D3S2_M21_EMPTY_CARRIER_EMPTY_SECONDARY` | 21 | `mode21_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 1 | `D3S2_M22_EMPTY_CARRIER_EMPTY_SECONDARY` | 22 | `mode22_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 2 | `D3S2_M23_EMPTY_CARRIER_EMPTY_SECONDARY` | 23 | `mode23_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 3 | `D3S2_M24_EMPTY_CARRIER_EMPTY_SECONDARY` | 24 | `mode24_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 4 | `D3S2_M25_EMPTY_CARRIER_EMPTY_SECONDARY` | 25 | `mode25_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 5 | `D3S2_M26_EMPTY_CARRIER_EMPTY_SECONDARY` | 26 | `mode26_empty_carrier_empty_secondary_ok` | OK | 0 | — | smoke |
| 6 | `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK` | 25 | `mode25_cum_total1_recent_slot1_anchor_ok` | OK | 8 | — | M25+ |
| 7 | `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT` | 25 | `mode25_recent_without_cum_carrier_absent_corrupt` | STORAGE_CORRUPT | 1 | — | M25− |
| 8 | `D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK` | 26 | `mode26_es_resume1_mgmt_resume_anchor_ok` | OK | 2 | — | M26+ |
| 9 | `D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT` | 26 | `mode26_mgmt_without_es_carrier_absent_corrupt` | STORAGE_CORRUPT | 1 | — | M26− |
| 10 | `D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK` | 24 | `mode24_rc_reply1_receipt_delivery_ok` | OK | 6 | — | M24+ |
| 11 | `D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT` | 24 | `mode24_rr_without_rc_carrier_absent_corrupt` | STORAGE_CORRUPT | 1 | — | M24− |
| 12 | `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK` | 23 | `mode23_tx_state_slots_L_equation_anchor_ok` | OK | 12 | — | M23+ |
| 13 | `D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT` | 23 | `mode23_evidence_without_state_carrier_absent_corrupt` | STORAGE_CORRUPT | 1 | — | M23− |
| 14 | `D3S2_M22_RC_APP1_ATT_DLV_OK` | 22 | `mode22_rc_app1_dlv_attempt_delivery_ok` | OK | 5 | — | M22+ |
| 15 | `D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT` | 22 | `mode22_att_without_rc_carrier_absent_corrupt` | STORAGE_CORRUPT | 1 | — | M22− |
| 16 | `D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK` | 21 | `mode21_state_cum1_att_tx_aii_anchor_ok` | OK | 7 | — | M21+ |
| 17 | `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT` | 21 | `mode21_att_without_aii_index_pair_absent_corrupt` | STORAGE_CORRUPT | 5 | — | M21− |
| 18 | `D3S2_M25_TWO_OWNER_SHA_INTERLEAVE_DUAL_CARRIER_OK` | 25 | `mode25_two_owner_sha_interleave_dual_carrier_ok` | OK | 16 | — | **P0-A** (#59) |
| 19 | `D3S2_M26_ES_MGMT_BUDGET_MID_FOCUS_RESUME_OK` | 26 | `mode26_es_mgmt_budget_mid_focus_resume_ok` | OK | 2 | — | **P0-B** (#60) |
| 20 | `D3S2_M25_BIND_EXACT_GET_PORT_FAILURE_NOTE0` | 25 | `mode25_bind_exact_get_port_failure_note0` | STORAGE | 6 | **0** | **P0-C** (#61) |
| 21 | `D3S2_M22_ATT_UNEXPECTED_AII_INDEX_PRESENT` | 22 | `mode22_att_unexpected_aii_index_present_corrupt` | STORAGE_CORRUPT | 5 | — | **P0-D** (#62) |
| 22 | `D3S2_M22_ATT_TRUE_PRIMARY_DELIVERY_ABSENT` | 22 | `mode22_att_true_primary_delivery_absent_corrupt` | STORAGE_CORRUPT | 4 | — | **P0-D** |
| 23 | `D3S2_M21_ATT_PRIMARY_PVD_MISMATCH` | 21 | `mode21_att_primary_pvd_mismatch_corrupt` | STORAGE_CORRUPT | 4 | — | **P0-D** |
| 24 | `D3S2_M21_ATT_INDEX_PAIR_SUBJECT_RAW_MISMATCH` | 21 | `mode21_att_index_pair_subject_raw_mismatch_corrupt` | STORAGE_CORRUPT | 5 | — | **P0-D** |

`note_count` 列: JSON `expected` にフィールドがあるのは **P0-C の 1 件だけ**（値 `0`）。他はフィールド無し。C fixture / production bridge は `note_count` を持たない・比較しない。

### Peer-get production bridge（PR #59 以降）

`tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` `run_vector`:

- Port-trace から peer `get` を数え、`baseline_gets == 17`（profile）を差し引く。
- `REQUIRE(observed_peer_gets == vec->expected.d3_peer_get_count)`。
- `REQUIRE((uint64_t)spy.get_calls - baseline_gets == vec->expected.d3_peer_get_count)`。

これは prior audit の「bridge が `d3_peer_get_count` を比較しない」ギャップを **全 25 suffix で閉じた** 実測である。

---

## 4. PR #59..#62 / P0 slice reflection

| PR / commit | Slice | Formal IDs | What closed |
| --- | --- | --- | --- |
| **#59** `a9d2b51` | **P0-A** multi-owner SHA | `D3S2_M25_TWO_OWNER_SHA_INTERLEAVE_DUAL_CARRIER_OK` | cases **2**, **6** core: two TX owners, SHA256_COMPOSITE RETRY band ABAB, dual CUM SELECT once under `last_carrier_key`, peer_get=16 |
| **#60** `f43a19e` | **P0-B** budget resume | `D3S2_M26_ES_MGMT_BUDGET_MID_FOCUS_RESUME_OK` | case **13**: mid-FOCUS `row_budget` stop (B5) + same-iterator resume (not B11); call checkpoints `cp_begin_calls=1`, `cp_focus_live`, `cp_observed_*`, `cp_last_carrier_key_*` |
| **#61** `c0f15f7` | **P0-C** Port BIND + two-txn | `D3S2_M25_BIND_EXACT_GET_PORT_FAILURE_NOTE0` + self-test two-txn | case **11** BIND get Port path; case **7** two-txn anti-pass; unit mid-FOCUS Port |
| **#62** `fec9edb` | **P0-D** BIND primary/pair | 4 vectors (unexpected INDEX, true-primary ABSENT, PVD mismatch, pair subject raw) | cases **8**, **15** constructible residuals |

### P0-C unit (mid-FOCUS; not formal)

| Unit | Path covered |
| --- | --- |
| `test_d3s2_p0c_bind_exact_get_port_failure_note0` | Mode25 BIND exact_get Port IO_ERROR → sticky `STORAGE`, FAILED, BIND mask incomplete, no fabricated CORRUPT |
| `test_d3s2_p0c_mid_focus_iter_next_port_failure_note0` | Mode26 mid-FOCUS `iter_next` Port IO_ERROR after ≥1 FOCUS OK → sticky `STORAGE`, no CORRUPT |

Formal mid-FOCUS Port vector は **無い**（case 11 residual）。

### `note_count=0` boundary（維持）

| Layer | What is proved |
| --- | --- |
| JSON formal | P0-C vector `expected.note_count == 0`（reference model only） |
| Generator | documents H3: Port → no `note_terminal_corrupt` |
| Production bridge | sticky `STORAGE` / phase FAILED / incomplete BIND / exact fault+trace; **does not count** `note_terminal_corrupt` |
| Unit P0-C | asserts `sticky == STORAGE` and `!= STORAGE_CORRUPT`; **no** note call counter |

**Boundary kept:** formal `note_count=0` ≠ production call-counter measurement.

---

## 5. True-primary raw mismatch: unconstructible analysis

Normative BIND step 3（§18.13.9）: true primary `ABSENT | live VALUE_DIGEST != expected PVD | raw bijection fail` → `note_terminal_corrupt`.

### Production path (exists)

`verify_true_primary_pvd_and_raw` in `domain_store_d3s2.c`:

1. `exact_get` rebuilt true-primary complete key（ANCHOR / DELIVERY）.
2. Port fail → sticky, **no note**.
3. ABSENT → `note_finding`.
4. `VALUE_DIGEST` vs expected PVD → note on mismatch.
5. Typed validate + raw identity: ANCHOR `transaction_id` vs `focus_tx_id`; DELIVERY `delivery_key_raw` vs `focus_raw80`.

### Why true-primary **raw** mismatch is not a constructible formal under prior invariants

Under **one** `READ_ONLY` snapshot and **D1 same-record validation** on the row returned by `exact_get` at the rebuilt complete primary key:

1. The true-primary key is rebuilt from the secondary’s owner raw / tx id already copied into BIND scratch.
2. A PRESENT row at that key must pass D1 typed validate. D1 same-record for ANCHOR / DELIVERY requires body identity to match the key identity (docs/17 primary/secondary same-record contracts; ANCHOR body `transaction_id` = key id; DELIVERY body `delivery_key_raw` = key contents).
3. Therefore, after PRESENT + typed validate, the body raw compared in step 5 is **identity-tautological** with the rebuild inputs: a fixture cannot expose “same key, validated row, wrong body raw” without violating D1 or inventing a second value at the same key inside one RO snapshot.
4. Observable divergences that **are** constructible:
   - true-primary **ABSENT**（P0-D formal `D3S2_M22_ATT_TRUE_PRIMARY_DELIVERY_ABSENT` + unit `test_d3s2_p0d_mode22_true_primary_delivery_absent`）
   - true-primary **PVD mismatch**（P0-D formal `D3S2_M21_ATT_PRIMARY_PVD_MISMATCH` + unit `test_d3s2_p1_mode21_bind_primary_pvd_mismatch`）
   - **pair peer subject/raw** mismatch after primary proven（P0-D formal `D3S2_M21_ATT_INDEX_PAIR_SUBJECT_RAW_MISMATCH`）

**Verdict for true-primary raw mismatch sub-claim:**
`UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS` — **not** “implementation missing”.

**Substitute used (must not be confused with true-primary raw):**
pair-subject residual `D3S2_M21_ATT_INDEX_PAIR_SUBJECT_RAW_MISMATCH` proves BIND pair body subject/raw fail **after** carrier+primary proven. Generator and bridge explicitly state this is **not** true-primary raw coverage.

---

## 6. §18.13.15 case classes 1..21

### Status counts

| Status | Count | Case #s |
| --- | ---: | --- |
| `FORMAL_ORACLE_AND_PRODUCTION_BRIDGE` | **11** | 1, 2, 6, 7, 8, 9, 13, 15, 16, 18, 21 |
| `PRODUCTION_AND_UNIT_ONLY` | **0** | — |
| `PARTIAL` | **9** | 3, 4, 5, 10, 11, 12, 14, 19, 20 |
| `MISSING` | **1** | 17 |
| `UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS` | **0** as whole-case status | (sub-claim of case 8 only; see §5) |

Delta vs prior audit @112 vectors: FORMAL 4→**11**; PARTIAL 14→**9**; MISSING 3→**1**（only DSD1 remains MISSING）。

### Per-case table

| # | Case class (Normative) | Status | Formal IDs / unit / production / unproved |
| ---: | --- | --- | --- |
| 1 | Modes 21–26 positive ordinary counts（plan ABSENT）— one mode per session | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal+: `D3S2_M21_STATE_CUM1_ATT_TX_AII_ANCHOR_OK`, `D3S2_M22_RC_APP1_ATT_DLV_OK`, `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK`, `D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK`, `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK`, `D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK` (+ empties 0..5). Bridge: `run_vector`. Production: `ninlil_domain_scan_begin_profiled_d3s2`, `ninlil_domain_scan_d3s2_drive`. **Unproved richness:** multi-count A/B/C>1 / cancel-lane formal density beyond minimal 1-row positives. |
| 2 | SHA non-contiguous multi-owner interleave | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: `D3S2_M25_TWO_OWNER_SHA_INTERLEAVE_DUAL_CARRIER_OK`（ABAB CUM/CUM/REC/REC; peer=16）. Production: SELECT + `last_carrier_key` frontier in `domain_store_d3s2.c`. **Unproved:** multi-owner formal for modes other than 25（Mode25 is representative for case core）. |
| 3 | Known-slot evidence/reply/retry presence matrix + illegal slot/kind | **PARTIAL** | Formal success matrix: Mode23/24/25 positives above. Unit illegal/missing: `test_d3s2_p0_8_mode23_slot_presence_required`, `test_d3s2_p0_7_mode24_declared_missing_reply_fail`. Production: FOCUS known-slot + `focus_close_compare`. **Unproved:** formal illegal-slot / illegal-kind / missing-slot corrupt vectors. |
| 4 | Stream attempt/index/management under/over count | **PARTIAL** | Unit: `test_d3s2_p0_2_no_select_residual_double_count`, `test_d3s2_mode26_management_count_mismatch`. Production: `focus_close_compare` Mode21/22/26. **Unproved:** formal under/over stream fail for Mode21 A/B/C, Mode22 app/cancel, Mode26 ordinary overcount（pair-absent Mode21 uses CLEANUP skip path, not ordinary INDEX undercount）. |
| 5 | CLEANUP_PLAN PRESENT → Mode21/22 ordinary skip; 23–26 still ordinary | **PARTIAL** | Formal Mode21 skip-shaped corrupt: `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT`（CP PRESENT / cleanup_skip）. Unit: `test_d3s2_p0_5_cleanup_plan_true_primary_skip`. Production: `apply_cleanup_plan_gate`. **Unproved:** Mode22 cleanup formal; Modes 23–26 “plan PRESENT still ordinary” formal anti-skip. |
| 6 | Carrier cursor no-skip / no-dup; last_carrier_key; mode-dependent carrier set | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal multi-carrier: P0-A dual CUM SELECT exactly once. Empties + per-mode carrier positives exercise mode-dependent carrier sets. Production: install/compare `last_carrier_key`. Unit residual: `test_d3s2_p0_2_no_select_residual_double_count`. **Unproved richness:** multi-carrier formal outside Mode25. |
| 7 | Same-txn multipass Port trace; two-txn harness fail | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: every d3s2 vector single `begin:READ_ONLY` + sequential `iter_open:prefix0`. Bridge: `begin_calls == 1` + exact port_trace. Generator self-test: `two_txn_list_count_port_trace_tamper`, `two_txn_smoke_begin_double_tamper`. Unit same-txn: `test_d3s2_baseline_reopen_pass_internal_freeze`. **Unproved:** production executable that drives a deliberate two-txn list-then-count API sequence（anti-pass is oracle/self-test + begin pin, not a live two-txn product run）. |
| 8 | BIND missing true primary / PVD / raw / Mode21 pair / Mode22 unexpected INDEX | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: `D3S2_M22_ATT_TRUE_PRIMARY_DELIVERY_ABSENT`, `D3S2_M21_ATT_PRIMARY_PVD_MISMATCH`, `D3S2_M21_ATT_WITHOUT_AII_INDEX_PAIR_ABSENT`, `D3S2_M22_ATT_UNEXPECTED_AII_INDEX_PRESENT`, `D3S2_M21_ATT_INDEX_PAIR_SUBJECT_RAW_MISMATCH`. Unit: `test_d3s2_p0d_mode22_true_primary_delivery_absent`, `test_d3s2_p1_mode21_bind_primary_pvd_mismatch`, `test_d3s2_p1_mode21_bind_index_pair_absent`. Production: `bind_attempt_row`, `verify_true_primary_pvd_and_raw`, `verify_index_pair_for_attempt`. **Sub-claim:** true-primary **raw** mismatch = `UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS`（§5）; substituted by pair subject raw formal — **not** claimed as true-primary raw. |
| 9 | BIND missing declared-count carrier / wrong carrier body subject | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal orphans: `D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT`, `D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT`, `D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT`, `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT`, `D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT`. Unit: `test_d3s2_p1_mode21_bind_carrier_absent`. Production: BIND step2 companion ABSENT → `note_finding`. **Unproved richness:** wrong-subject carrier body formal beyond ABSENT class. |
| 10 | Count green without that mode’s BIND set → must not pass | **PARTIAL** | Production COMPLETE requires mode `binding_complete_mask` full. Unit: `test_d3s2_incomplete_finalize_reject_then_abort`. **Unproved:** formal anti-pass where focus counts are green but BIND omitted/incomplete and COMPLETE is rejected. |
| 11 | Port terminal mid-FOCUS/BIND（carrier/primary/pair gets）→ note 0 | **PARTIAL** | Formal BIND Port: `D3S2_M25_BIND_EXACT_GET_PORT_FAILURE_NOTE0`（STORAGE, peer=6, JSON `note_count=0` reference-only）. Unit BIND: `test_d3s2_p0c_bind_exact_get_port_failure_note0`. Unit mid-FOCUS: `test_d3s2_p0c_mid_focus_iter_next_port_failure_note0`. Production H3: Port → no undercount/orphan note. **Unproved:** formal mid-FOCUS Port vector; production **note call counter** measurement（JSON-only boundary retained）. |
| 12 | Profile mismatch / future candidate → S2 evaluator 0; INTERNAL must not clear baseline flags | **PARTIAL** | Unit freeze-when-clear: `test_d3s2_baseline_reopen_pass_internal_freeze`. Production: `ninlil_domain_scan_d3s2_on_row` early-out when mismatch/future set. Formal vectors all ship mismatch/future = 0. **Unproved:** formal/unit that **sets** profile_mismatch or future and proves S2 notes 0 / flags frozen under INTERNAL. |
| 13 | Budget mid-focus resume（B5, not B11） | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: `D3S2_M26_ES_MGMT_BUDGET_MID_FOCUS_RESUME_OK` with call-level checkpoints (`cp_begin_calls=1`, focus_live, observed, last_carrier_key). Bridge runs call sequence + peer_get=2. Production drive B5/B6. Unit still has B0 only (`test_d3s2_drive_budget_zero`) as secondary. |
| 14 | Empty secondary vs declared>0; empty-carrier BIND; empty+secondary orphan | **PARTIAL** | Formal empty×6 COMPLETE + case-9 empty-carrier+secondary orphans. Unit: `test_d3s2_empty_carrier_empty_secondary_success`. **Unproved:** formal “carrier PRESENT, declared>0, secondary empty → ordinary undercount CORRUPT”. |
| 15 | Mode22 INDEX expect 0 via BIND_ATTEMPT ABSENT; unexpected INDEX; Mode21 BIND_INDEX no STATE companion | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal unexpected: `D3S2_M22_ATT_UNEXPECTED_AII_INDEX_PRESENT`. Formal INDEX ABSENT success: `D3S2_M22_RC_APP1_ATT_DLV_OK`. Mode21 BIND_INDEX no-STATE pin: success `d3_peer_get_count=7` + bridge pin + production `bind_index_row` comment/code. **Unproved richness:** none required for case core after P0-D. |
| 16 | Mode25 RECENT-without-CUM → carrier fail; CUM self-carrier primary-only | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | Formal: `D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT`, `D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK`. Unit: `test_d3s2_mode25_recent_without_cumulative_fail`. Production: `BIND_RETRY` CUM self-carrier skip companion get. |
| 17 | DSD1 composition fixtures（multi-session S1+S2; not Mode 28; not dual-bound） | **MISSING** | §18.13.16 composition-only. `domain-scan-composition-v1.json` is **D2-S5** only. **No** harness chaining `begin_profiled_d3s1` + `begin_profiled_d3s2` sessions on one DSD1 fixture with DONE between. Dual-bound forbidden is scanner begin enforcement, not DSD1 product proof. |
| 18 | exact 94 d3s1 prefix retained after append | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | `d3s1_prefix_count=94`, generator `check`, bridge `NINLIL_D3S1_VECTOR_COUNT == 94u`, CMake fixture freshness pin. |
| 19 | Mode23 `valid = M + overflow` equation + late coherence without false late equality | **PARTIAL** | Formal success equation: `D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK`. Unit: `test_d3s2_mode23_nonempty_success`. Production: `focus_close_compare` equation. **Unproved:** formal equation-fail and late-coherence-fail vectors. |
| 20 | Six-session product: harness must not assume one baseline covers six modes | **PARTIAL** | Structural: six independent empty smokes (modes 21..26) each own begin; bridge one mode per vector. **Unproved:** anti-pass rejecting multi-mode / one-session-all-six COMPLETE product claim. |
| 21 | Get-budget freeze: BIND ≤1 primary + ≤1 carrier + ≤1 pair（max 3 ATTEMPT） | **FORMAL_ORACLE_AND_PRODUCTION_BRIDGE** | All 25 formal vectors ship `d3_peer_get_count`; generator check pins key vectors; **production bridge compares peer_get for every suffix vector**. Mode21 success notes ATTEMPT≤3 INDEX≤2. **Unproved richness:** formal unbounded-get anti-pass / explicit per-row budget field（session totals match production; not a separate per-row counter artifact）. |

---

## 7. Remaining gaps (do not overlook)

| Gap class | Cases | Evidence state |
| --- | --- | --- |
| DSD1 multi-session composition | 17 | **MISSING** |
| Stream under/over formal | 4 | PARTIAL |
| CLEANUP Modes22–26 formal matrix | 5 | PARTIAL |
| Known-slot illegal/equation-fail | 3, 19 | PARTIAL |
| Empty secondary declared>0 ordinary fail | 14 | PARTIAL |
| Count-green-without-BIND anti-pass | 10 | PARTIAL |
| Profile/future evaluator-off formal | 12 | PARTIAL |
| mid-FOCUS Port formal + note counter | 11 residual | PARTIAL; `note_count` JSON-only boundary |
| Six-session multi-mode anti-pass | 20 residual | PARTIAL |
| True-primary raw | 8 sub-claim | **UNCONSTRUCTIBLE**（do not schedule as “implement raw formal”） |

---

## 8. Reference existence map（audit-time `rg` / extract）

| Reference | Exists |
| --- | --- |
| Formal IDs in §3 table | yes in `spec/vectors/domain-scan-crossrow-v1.json` |
| `ninlil_domain_scan_begin_profiled_d3s2` | `src/runtime/domain_store_scanner.c` |
| `ninlil_domain_scan_d3s2_drive` | `src/runtime/domain_store_d3s2.c` |
| `verify_true_primary_pvd_and_raw`, `bind_attempt_row`, `apply_cleanup_plan_gate`, `focus_close_compare` | `domain_store_d3s2.c` |
| Unit names cited in §6 | `tests/runtime/domain_store_d3s2_test.c` |
| Bridge peer_get compare + 25 count pin | `domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c` |
| CMake `NINLIL_D3S2_VECTOR_COUNT ((size_t)25u)` freshness | `CMakeLists.txt` |

---

## 9. Overall verdict

# **NOT COMPLETE**

**Can D3-S2 complete be claimed?** **NO.**

Evidence summary:

- Formal sibling advanced to **119 = 94 + 25** with production peer-get bridge and P0-A..D closed for their targeted cores.
- **9** case classes remain **PARTIAL**; **1** (**DSD1**, case 17) remains **MISSING**.
- `note_count=0` is still formal-reference-only.
- True-primary raw is unconstructible under D1+RO — not a reason to claim “all BIND bullets green without documentation”.
- §18.13.18: D3-S2 implementation complete requires six mode sessions **and** code/oracle covering the minimum anti-false-pass set — not satisfied while PARTIAL/MISSING remain.
- Does **not** claim D3 overall / S3–S12 / Stage 5 / public Runtime / ESP-IDF / hardware.

S2a historical freeze text must **not** be rewritten to “implementation complete”.

---

## 10. Next implementation slices（P1 / P2）

Principles: append-only formal preferred for completion; unit alone insufficient; do not rewrite S2a freeze; do not dual-bind S1+S2; do not invent Mode 28; do not schedule true-primary raw formal.

### P1 — anti-false-pass ordinary / cleanup / known-slot / evaluator

#### Slice P1-A: Stream under/over + empty-secondary declared>0
- **Cases:** 4, 14
- **Work:** append formal vectors for Mode21 A/B/C under and/or overcount; Mode22 app/cancel under/over; Mode26 management overcount; at least one “carrier PRESENT + declared>0 + empty secondary band → CORRUPT”.
- **Acceptance:** new IDs in d3s2 suffix; independent expected; production bridge green including `d3_peer_get_count`; generator check pins.
- **Formal ID candidates:** `D3S2_M21_ATT_STREAM_OVERCOUNT_*`, `D3S2_M22_APP_UNDERCOUNT_*`, `D3S2_M26_MGMT_OVERCOUNT_*`, `D3S2_M24_RC_DECLARED_REPLY_EMPTY_SECONDARY_*`（exact names generator-owned）.
- **Forbidden:** rewriting existing 119-prefix objects; CLEANUP_PLAN skip as substitute for ordinary undercount.

#### Slice P1-B: CLEANUP_PLAN matrix Modes22–26
- **Cases:** 5
- **Work:** Mode22 CLEANUP PRESENT ordinary-skip formal; Modes 23–26 plan PRESENT still run ordinary FOCUS/BIND（anti false-skip）.
- **Acceptance:** formal IDs + bridge; production `cleanup_skip` assertions where applicable.
- **Formal ID candidates:** `D3S2_M22_CLEANUP_PLAN_*`, `D3S2_M23_CLEANUP_PLAN_STILL_ORDINARY_*`（and 24–26 as needed; split PRs if >2 modes）.
- **Forbidden:** claiming Modes 23–26 skip ordinary under CLEANUP.

#### Slice P1-C: Known-slot illegal + Mode23 equation/late fail
- **Cases:** 3, 19
- **Work:** illegal slot/kind formal; Mode23 equation fail; late coherence fail without requiring false late equality.
- **Acceptance:** formal + bridge; unit optional secondary.
- **Formal ID candidates:** `D3S2_M23_ILLEGAL_SLOT_*`, `D3S2_M23_EQUATION_FAIL_*`, `D3S2_M23_LATE_COHERENCE_FAIL_*`, `D3S2_M24_ILLEGAL_REPLY_KIND_*`, `D3S2_M25_ILLEGAL_RETRY_SLOT_*`.
- **Forbidden:** semantic-only abstract cases as completion.

#### Slice P1-D: Count-without-BIND anti-pass + profile/future evaluator-off
- **Cases:** 10, 12
- **Work:** (1) fixture/path where counts would pass but BIND incomplete → not COMPLETE; (2) profile_mismatch and/or future_profile_candidate set with S2 evaluator notes 0 and INTERNAL not clearing baseline flags.
- **Acceptance:** formal preferred; if harness-level only, document as such and keep case PARTIAL until formal.
- **Formal ID candidates:** `D3S2_M2x_COUNT_GREEN_BIND_INCOMPLETE_*`, `D3S2_M2x_PROFILE_MISMATCH_EVALUATOR_OFF_*`, `D3S2_M2x_FUTURE_CANDIDATE_EVALUATOR_OFF_*`.
- **Forbidden:** using S1 dual-bind; clearing baseline counters under PASS_INTERNAL.

#### Slice P1-E: mid-FOCUS Port formal residual（optional close for case 11）
- **Cases:** 11 residual
- **Work:** formal Mode26 (or Mode21 stream) mid-FOCUS `iter_next` Port IO_ERROR after ≥1 OK; sticky STORAGE; incomplete focus; **retain** `note_count` JSON-only boundary unless a production note counter seam is Normatively added（out of scope unless separate docs freeze）.
- **Acceptance:** formal ID + bridge Port path; do not invent production note_count counter in this slice.
- **Forbidden:** asserting production note call counts without a real seam.

### P2 — composition / product honesty

#### Slice P2-A: DSD1 multi-session composition
- **Cases:** 17
- **Work:** multi-session harness chaining S1 modes 11/14/17/19 + S2 modes 22/23/24 on one fixture; cleanup DONE between sessions; never dual-bound. Prefer new composition sibling or documented multi-session orchestration vectors — **not** Mode 28.
- **Acceptance:** orchestrated evidence that §18.13.16 pieces compose; S2 alone still does not claim DSD1 complete.
- **Forbidden:** Mode 28; dual-bound S1+S2; claiming Writer E2E / D4.

#### Slice P2-B: Six-session product anti-pass
- **Cases:** 20 residual
- **Work:** generator/bridge reject multi-mode vectors or one-session-all-six COMPLETE expectations; document product cost honesty.
- **Acceptance:** self-test / check gate; no production algorithm change required if already 1 mode/session.
- **Forbidden:** one-session all six modes product.

#### Slice P2-C: Re-audit → complete claim（separate change set）
- After P1+P2-A/B, re-run this audit template on a new fixed commit.
- Only then a **separate** change set may advance “D3-S2 implementation complete” status language **outside** S2a historical freeze text.
- Do not rewrite §18.13.18 S2a historical row.

### Recommended order

1. **P1-A**（stream / empty-secondary — highest false-green risk for ordinary counts）
2. **P1-D**（count-without-BIND + profile/future — COMPLETE false-pass risk）
3. **P1-B** then **P1-C**（cleanup / known-slot / equation）
4. **P1-E** if case 11 residual still blocks re-audit consensus
5. **P2-A** DSD1
6. **P2-B** product anti-pass
7. **P2-C** completion claim change set

---

## 11. Exit gate: after D3-S2 complete → Portable Core → POSIX / ESP-IDF

This gate is **only** for leaving **D3-S2** as complete and allowing the portable core stack to proceed toward host/target builds. It is **not** Stage 5 complete, **not** D3 overall complete, **not** ESP-IDF product complete.

### D3-S2 exit gate（must all hold）

| # | Gate |
| ---: | --- |
| G1 | Fixed commit has formal sibling check green at current pin; 94 d3s1 prefix identity retained |
| G2 | All §18.13.15 cases 1..21 are `FORMAL_ORACLE_AND_PRODUCTION_BRIDGE` **or** documented `UNCONSTRUCTIBLE_UNDER_PRIOR_INVARIANTS` with Normative/D1 rationale（no silent MISSING/PARTIAL） |
| G3 | Modes 21..26 each have self-contained session evidence; product is six sessions, not one-session-all-six |
| G4 | Production bridge green for full d3s2 suffix; `d3_peer_get_count` compared; mutation_calls=0; single RO txn per vector |
| G5 | DSD1 composition evidence exists as multi-session orchestration（case 17）without Mode 28 / dual-bind |
| G6 | Separate status change set records “D3-S2 implementation complete” **without** rewriting S2a historical freeze text |
| G7 | Explicit non-claims remain: D3-S3..S12 / D3 overall / Stage5 D3 bind / public Runtime / D4 writer E2E / hardware |

### Portable Core → POSIX / ESP-IDF（post-S2 only）

Per `docs/07-testing-and-quality.md` layers: pure unit/conformance and golden vectors remain portable; target firmware build（layer 9）and HIL（layer 10）are **later** gates.

| Step | Allowed after G1–G7 | Still forbidden to claim |
| --- | --- | --- |
| Portable Core private S2 APIs used in host CI | yes | public Runtime freeze complete |
| POSIX host Port integration tests for scanner/S2 seams | yes | Stage 5 `storage_recovery_complete=1` |
| ESP-IDF **target build** of portable core that already contains complete S2 | yes as **build** evidence | ESP-IDF Domain Store / Stage5 D3 bind complete; RF/HIL complete |
| Continue D3-S3..S12 on portable core | yes（next D3 slices） | “D3 complete” |

**Confusion guard:** completing D3-S2 does **not** mean Stage 5, D3 overall, or ESP-IDF product done. ESP-IDF is a **downstream packaging/target** concern after portable completeness of the claimed slice.

---

## 12. Non-claims (explicit)

This re-audit does **not** claim:

- D3-S2 implementation complete
- D3 complete / S3–S12 complete
- Stage 5 complete / Stage5 D3 bind
- public Runtime / D4 writer E2E
- ESP-IDF / USB / LoRa / hardware complete
- production measurement of `note_count`
- true-primary raw formal constructibility
- semantic oracle full wire realization

---

## 13. Change control

- This file is **non-normative**.
- Only this path was added: `docs/reviews/2026-07-12-d3s2-post-p0-reaudit.md`.
- Normative docs / production / tests / tools / vectors / CMake / prior audit were **not** modified.
- No Web / subagent / commit / push / checkout / rebase performed for this audit.

### Verification performed while writing

| Check | Result |
| --- | --- |
| `python3 tools/domain_scan_crossrow_d3s2_vector_gen.py check ...` | ok; 119; content_sha256 pin above |
| Generator `self-test` | ok（includes two-txn anti-pass） |
| Mechanical ID/status/peer_get extract vs §3 table | match |
| `rg` formal IDs / unit names / production symbols | present |
| `git diff --check` | run after write（this file only expected） |
