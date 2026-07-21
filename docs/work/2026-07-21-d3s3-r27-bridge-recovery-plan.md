# D3-S3 R27 oracle候補 / production bridge 件数不一致回収 — トランチ実装計画

状態: **rev2**（Sol high NO-GO P0=4/P1=10/P2=2 の該当分を反映; 再レビュー待ち）
作成: 2026-07-21 / orchestrator: Fable
worktree: `/Users/dt/job/LoRa/ninlil-d3s3-implementation` branch `codex/d3s3-implementation`（dirtyユーザー資産; 巻き戻し禁止）

## 1. 証拠ベースの現状監査（実測）

| 項目 | 実測値 |
| --- | --- |
| `spec/vectors/domain-scan-crossrow-v1.json` | vector_count **280** = prefix 144 + suffix **136**（production `rep1_l2` **135** + `formal_precheck` **1**）。raw SHA-256 全値 `1506f43229b27254e70cc8fc54faa039711007924d015c451a3fd23114d59fe2`（検査: `shasum -a 256 spec/vectors/domain-scan-crossrow-v1.json`） |
| generator `check` | **green**: `check ok vectors=280 suffix=136 production=135 formal_precheck=1 blob_vecs=123 afp=[1..17]` |
| bridge test count pin | 旧 125/124（R18残骸）→ **136/135へ追従済み**（本トランチ内; 未commit） |
| pin追従後のbridge実行 | **RED 9 vectors / green 126**（下表; R26由来2本 + R27-Sol追加7本 = generator列挙と一致） |
| review memo `docs/reviews/2026-07-20-…md` | 内部矛盾: 冒頭表 280/136/135、後半表 273/129/128（R26残骸行）→ 本トランチで280/136/135へ整合 |

### RED 9 vectors（すべて Mode27 EventFact cross-row CORRUPT 系; unique ID数=9）

| # | Vector ID | 現productionの誤動作 |
| ---: | --- | --- |
| 1 | `D3S3_M27_EF_TERMINAL_ACTIVE_CORRUPT` | CORRUPTは出すが checkpoint `lifecycle_class`=3(ILLEGAL_CARRIER)。期待は **0(NONE)**（同一vectorの複数assert差分は1本と数える） |
| 2 | `D3S3_M27_EF_NONTERM_RELEASED_CORRUPT` | nonterminal+RELEASED を HISTORICAL と誤分類し false-green |
| 3 | `D3S3_M27_EF_DS_STATE_FAMILY_CORRUPT` | family (EF anchor ⇔ STATE `deadline_verdict==NA(4)`) 未検査 |
| 4 | `D3S3_M27_EF_STATE_AVD_PVD_FOREIGN_CORRUPT` | STATE `anchor_value_digest` / envelope common PVD 未検査 |
| 5 | `D3S3_M27_EF_SPOOL_PVD_FOREIGN_CORRUPT` | spool envelope common PVD 未検査 |
| 6 | `D3S3_M27_EF_REV_MISMATCH_CORRUPT` | STATE `event_spool_revision` == spool `spool_revision` == common `record_revision` 未検査 |
| 7 | `D3S3_M27_EF_PARKED_ACTIVE_CORRUPT` | STATE PARKED + ACTIVE spool を許容 |
| 8 | `D3S3_M27_EF_READY_PARKED_CORRUPT` | STATE READY + PARKED spool を許容 |
| 9 | `D3S3_M27_EF_PARK_CAUSE_MISMATCH_CORRUPT` | STATE `event_park_cause` == spool `park_cause` 未検査 |

## 2. Normative契約（oracle `o1a_mode27_cross_row_ok` + RefSession から抽出; 完全版）

authority は oracle（generator + 280-vector JSON; SHA pinned）。**JSON/generator本体は本トランチで変更禁止**（review memoの件数整合はdocs修正のみ）。

### 2.1 want_avd の pin（SELECT pure-W）

- want_avd = carrier（ANCHOR）record **全valueの `ninlil_model_domain_value_digest`**。
- pin先slot = **`ctx->view_a_key_digest`**（規範754-layout map `carrier_value_digest → view_a_key_digest`; generator:5130-5133「Mode27 does not use dual-view / does not collide with man.expected_owner_pvd」、同期 generator:8094-8097、消費 generator:8957-8963）。Mode27 の production は view_a を一切使わないことを確認済み（使用箇所はMode28/30系のみ: d3s3.c 821/828/834/1643/1663/2756）。`expected_owner_pvd` は**使わない**（Sol high P0-1）。
- SELECT_SETUP消費後の当該slotはRefSessionどおり残置（Mode27では以後読まれない）。

### 2.2 cross-row閉積（SELECT_SETUP G; 両GET後・lifecycle分類前; oracle順）

1. family: `is_event_fact` ⇔ STATE.`deadline_verdict == NINLIL_DEADLINE_NOT_APPLICABLE(4)`。
2. STATE.`anchor_value_digest` == want_avd。
3. STATE envelope common `primary_value_digest` == want_avd。
4. STATE.`transaction_id` == anchor body先頭16B（= `ctx->focus_id16`）。
5. DesiredState: spool GETなし（既存どおり）。cross-rowはここまで。
6. EventFact: spool envelope common PVD == want_avd; spool.`transaction_id` == STATE.`transaction_id`; STATE.`event_spool_revision` == spool.`spool_revision`; spool envelope `record_revision` == spool.`spool_revision`。
7. state×spool×park閉積:
   - STATE PARKED → spool PARKED_RETRY(2) かつ `event_park_cause`==`park_cause` かつ park cause ∈ {1..5}。
   - nonterminal非PARKED → spool ACTIVE(1) のみ、かつ 両park cause 0。
   - terminal receipt（TERMINAL+SATISFIED+reason64+discarded=0）→ spool RELEASED(3)、両park 0。
   - terminal audited discard（TERMINAL+FAILED+reason80+discarded=1）→ spool DISCARDED(4)、両park 0。
   - その他のterminal形 → CORRUPT。

**失敗時の観測契約**: sticky `NINLIL_E_STORAGE_CORRUPT`、`lifecycle_class` **NONE(0)のまま**（ILLEGAL_CARRIER禁止）、phase 14、EFは `d3_peer_get_count == 2`、`adopted=0`、finalizeもCORRUPT。

### 2.3 閉積通過後のlifecycle分類（RefSession完全契約; Sol high P0-2反映）

EventFact（generator:8985-9045相当）:
- `hist_ok` = (receipt かつ spool RELEASED) または (audited discard かつ spool DISCARDED)。
- `live_ok` = nonterminal かつ **`explicitly_discarded == 0`** かつ（PARKED→spool PARKED_RETRY / 非PARKED→spool ACTIVE）。
- hist_ok: `focus_key_digest` 全零 → sticky CORRUPT（lifecycle NONEのまま）。非零 → HISTORICAL_ABSENT / expected_live=0。
- live_ok: dig零 → LIFE_NONE / expected_live=0。非零 → LIVE_REQUIRED / expected_live=1。
- どちらでもない → sticky CORRUPT（閉積(7)で既に排除されるが、fail-closedの網として維持）。

DesiredState:
- **`explicitly_discarded != 0` → RED**（既存維持; ただし本枠の観測契約に整合させる）。
- terminal → dig零ならRED、非零ならHISTORICAL_ABSENT / expected_live=0。
- nonterminal → dig零ならLIFE_NONE / expected_live=0、非零ならLIVE_REQUIRED / expected_live=1。

## 3. 編集範囲（限定; これ以外のファイルは触らない）

| ファイル | 変更 |
| --- | --- |
| `src/runtime/domain_store_d3s3.c` | §2どおり。`value_length` を `on_row_select`→`install_and_setup_carrier`→`pin_mode27_from_carrier` へthread-through（static関数; ABI影響なし。Sol high P1-1）。STATE側は次のGET前に **tx16 / avd32 / common PVD32 / deadline_verdict / event_spool_revision / event_park_cause**（既存4 scalarに追加）をdrive-localへコピー（workspace上書き対策; Sol high P1-1）。既存discard/released分岐は§2.2-2.3へ包摂・再編 |
| `tests/runtime/domain_store_scanner_crossrow_d3s3_oracle_bridge_test.c` | 件数pin 125/124→136/135（**済**） |
| `tests/runtime/domain_store_d3s3_test.c`（**実装後スコープ追加**） | Mode27単体テストのfixture/期待値が旧契約（placeholder PVD `0x55…`、avd不整合、CORRUPT時ILLEGAL_CARRIER期待）を固定化しており、oracle契約と原理的に両立不能なことがQwen実装で判明（6 REQUIRE失敗）。共有 `domain_store_d3s1_fixtures.h` はd3s1/d3s2テストも使用するため**変更禁止のまま**とし、d3s3テスト内でfixtureをmutable copy+avd/PVD/rev patch+CRC再計算のruntime導出でcross-row整合化し、CORRUPT期待をlifecycle NONE+sticky CORRUPTへ更新する |
| `docs/reviews/2026-07-20-d3s3-implementation-candidate.md` | 273/129/128残骸行を280/136/135へ整合、R28（production/bridge追従）を追記 |
| `docs/work/…` | 台帳・受入証拠 |

制約: public ABI / wire / vector JSON / generator 不変。context拡張禁止（sizeof 754 / align 1 / ceiling 768）。KGuard語彙のCore流入禁止。R16–R27の検査を弱めない。

## 4. 手順と役割

1. Qwen（OpenCode `alibaba-token-plan/qwen3.8-max-preview`）: §2/§3どおり実装。
2. Fable統合QA: §5受入条件の全証拠取得。
3. Grok（grok-4.5）diffレビュー + **Sol xhigh**境界レビュー（oracle/production境界）。
4. review memo更新（R28）→ 日本語commit → PR → CI green → main統合 → README更新 → push。

## 5. 受入条件（証拠必須）

1. bridge green: `domain_store_scanner_crossrow_d3s3_oracle_bridge OK (136 typed vectors; production=135 formal_precheck=1)` exit 0。
2. `domain_scan_crossrow_d3s3_fixture_freshness` green。
3. 全CTest green（通常build / ASan+UBSan build 両方）。strict warnings 0。
4. vector JSON raw SHA-256 == `1506f43229b27254e70cc8fc54faa039711007924d015c451a3fd23114d59fe2`（コマンド出力を記録）。
5. **無後退の個別確認（Sol high P1-2; bridge全走に含まれるが、以下を受入記録で個別に列挙確認）**:
   - `EVENTFACT_LIVE_OK` 系のACTIVE/PARKED live分類維持
   - `HISTORICAL_RECEIPT_OK` / `HISTORICAL_DISCARD_OK` 維持
   - DesiredStateのLIVE/HISTORICAL/NONE分類維持
   - STATE GET natural fault = **1 GETで元のStorage status**、SPOOL fault = **2 GET目でStorage status**（status precedence維持）
   - missing STATE/SPOOLのみCORRUPT（存在時は閉積判定）
   - manifest install後の `expected_owner_pvd` 上書きとOWNER_PVD_PROOFの無影響（slot分離により構造的に保証; view_a採用の根拠）
6. **build provenance記録（Sol high P2-2; 再レビュー反映）**: build dir、`git rev-parse HEAD`、**worktree全差分の決定的manifest hash**——tracked差分(staged含む)は `git diff HEAD | shasum -a 256`、untracked build inputは `git ls-files --others --exclude-standard | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256`（実装・テスト・generator自体がuntrackedのため両方必須）、生成fixture header SHA-256、compiler/sanitizer構成、実行コマンド、（修正前）全失敗ID一覧。
7. Grok P0/P1=0、Sol xhigh P0/P1=0。

## 5.5 監査中に回収した付随事項（2026-07-21実施済み）

- baseline全CTest実測: 230中3失敗 = 本トランチ対象bridge + `esp_storage_public_api_gate`(+self_test)。
- 後者2件の原因: untracked残骸2ファイル（`ports/esp-idf/storage/include/ninlil_port/esp_storage_workspace.h` と `docs/19-m3-esp-idf-durable-storage.md`）。いずれもcommit済み新版（`ports/esp-idf/storage/private/esp_storage_workspace.h` / `docs/21-…`）の旧draft重複で、gateは旧位置の存在自体をRED判定。
- 処置: 破棄禁止方針に従い `/Users/dt/job/LoRa/ninlil-attic/2026-07-21-d3s3-stale-drafts/` へ退避（bytes保全）。gate 2件green再確認済み。baseline赤は bridge 1件のみとなった。

## 6. リスク

- 既存126本の期待checkpointが現productionの分岐に依存 → §5-5の個別確認で担保。
- 閉積のfail-closed網（§2.3「どちらでもない」）が既存vectorのILLEGAL_CARRIER期待と衝突する可能性 → bridge全走 + 失敗時は当該vectorの期待checkpointをoracleから再抽出して追従。

## 7. レビュー履歴

| 日時 | レビュア | 結果 |
| --- | --- | --- |
| 2026-07-21 | Codex GPT-5.6 Sol high（計画rev1） | **NO-GO** P0=4 / P1=10 / P2=2（P0-1 pin slot誤り、P0-2 lifecycle契約不足、P0-3 RED件数矛盾、P0-4 master順序循環; P1/P2はmaster側中心） |
| 2026-07-21 | rev2（本書） | P0-1/P0-2/P0-3、P1-1/P1-2、P2-1/P2-2 を反映。P0-4とP1-3..10はmaster plan rev2で対応 |
| 2026-07-21 | Codex Sol high（rev2再レビュー） | 本書側の残指摘はP2=1（provenanceのuntracked未包含）のみ。P0/P1は本書分すべて解消確認 |
| 2026-07-21 | rev3（本書） | provenance manifestをtracked差分+untracked全build inputの決定的hashへ修正 |
