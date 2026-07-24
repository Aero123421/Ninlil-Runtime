# A2: D3-S4 `DSW1_ALL_OLD_NEW` witness member group 実装 — トランチ計画

状態: **rev2**（Sol high NO-GO P0=2/P1=6/P2=1 反映; 再レビュー待ち）
作成: 2026-07-21 / orchestrator: Fable
前提: A1(D3-S3回収)のPR #108 merge後に実装開始。branchは新規worktree（mainから）。

## 1. 規範authority（実測確認済み; Sol high P1-1反映）

- `docs/17` **§18.15 全域 = line 5176–5823**（D3-S4a docs freeze; 本文変更禁止。§18.15.18の歴史的"No"表も保存）。
- modes **31..34** / k₄=4、FOCUS_MEMBERS **2M+P**、MEMBERSHIP_DUAL full-M、Mode34 same-txn manifest SHA + arm A/B/C + carrier pin + `arm_cursor` closed enum + quota=1 progress（§18.15.8.4）、Mode31/32 SUPERSEDE deferred progression、Mode33 CHUNK_ORPHAN/header binding、same-txn primary PVD + closed byte-exact raw/raw2/aux normalization。
- **受理/拒否の正**（Sol high P0-1）: Mode31 ACTIVEは **ALL_NEWのみlocal valid**、ALL_OLD/MIXEDは**CORRUPT**。Mode32はOLD/MIXED/CORRUPT拒否、ALL_NEWまたはprogressed形を**deferred**（§18.15.6 :5331-5335）。precedenceはcorruption > deferred/local valid（:5339）、全体はD2/local decode CORRUPT > PVD/raw/head CORRUPT > missing…の閉順序（§18.15.10）。
- **exact get-budget全表**（§18.15.9 :5556-5566; Mode33/34含む）、vectorごとのexact get-count + quota=1 no-reissue。
- **実行環境拘束**（:5180-5182）: single READ_ONLY txn / single 4096 value / no heap/VLA/no second 4096 / S1等の別session結果代用禁止 / chunk borrow禁止 / 2-snapshot list-then-prove禁止 / full member-ID set保持禁止。
- **closed private result/publication**（:5583-5605）: scanner private resultへ**S4用2 field追加**、S4のみのwhole-object publication、abort無出力、disposition sample→cleanup→single copy→**context zero**の順序、whole-result poison不変（abort/cleanup failure/alias/incomplete finalize）。result field offsets **52/53**、host size/alignment、target `sizeof<=64`。
- **closed state/MBZ ownership**（:5678-5704）: phase/mask/enum/MBZの全不正値がRED。
- **mandatory oracle catalog**（**§18.15.15 :5762-5798**）: positive **11**項目 + negative/mutation **15**項目（Mode17/BLOB primary normalization row、M=2/M=9 index列、Mode31/32 direct disposition 3、higher composition、Mode33 RETIRED zero/partial、empty Arm A、whole-result poison/publication、raw/raw2/aux component mutation等）。bridgeはfull state transition / exact-get key sequence / masks / disposition / terminal result / Port fixture比較を要求（:5764,5780）。
- context: S4 `sizeof=949` / ceiling **960**。outer S1+S2+S4 **10112**（packed 10060/10064）/ full S1+S2+S3+S4 **10880**（packed 10814/10816）。scanner ceiling 8192不変。ESP task-stack high-waterはfinalize temporary最大**64B**込み（:5735-5749）。
- oracle系譜: crossrow append-only拡張（94→144→280）。D3-S4は **280-vector object authority不変 + d3s4 suffix** の `ninlil-domain-scan-crossrow-v1-d3s4`。
- 参考: freeze worktree `ninlil-grok-d3s4-freeze`（docsのみ; コード流用なし）。

## 2. 段階構成（D3-S3のR5..R27反復教訓を初回から独立ゲート化; Sol high P1-2/P1-3反映）

| 段階 | 内容 | ゲート |
| --- | --- | --- |
| A2-a | §18.15全域(5176-5823)から実行可能contract抽出: modes31..34 call/Port文法、per-mode phase機械、get-budget表、precedence、result/publication契約を新generator `tools/domain_scan_crossrow_d3s4_vector_gen.py` のRefSession骨格 + permanent self-test雛形として実装。**§18.15.15 の positive 11 + negative/mutation 15 の case-ID coverage matrixを固定**（A2-b終了条件の正）。vector未生成 | generator self-test green + Sol high契約抽出レビュー（coverage matrix含む） |
| A2-a2 | **独立fail-closedゲート群の先行実装**（D3-S3失敗様式の予防; Sol high P1-3）: (i)使用全family/subtype/body variantのD1 coverage・boundary・differential gate、(ii)header mode×action×OLD/NEW/NEITHER×head×predecessor lifecycle×group foldの**閉classifier matrix**、(iii)phase/mask/enum/MBZ全不正値matrix（:5682-5704）、(iv)CLI `generate/check/emit-c-fixture/self-test` のarity・scalar/non-object・bool/float/overflow・malformed nested・no-traceback・no-side-effect gate | 全gate permanent self-test green |
| A2-b | vector本文生成: positive = **Mode31 ALL_NEW / Mode32 deferred(S5, S5+S6)等の§18.15.15正リストのみ**。all-old/mixed/dup/missing/extra/partial/chunk orphan/head backlink/f3-4↔HEAD_INDEXは**negative/CORRUPT vector**。全suffix行D1-legality gate + coverage matrix **26/26 covered** + prefix authority pin（full-object equality + format/count=280/content SHA/raw SHA + duplicate ID・非決定生成・malformed既存出力のfail-closed; d3s3の :13516-13555 方式） | `check` green + D1 gate green + coverage 26/26 + Sol high oracle候補レビュー（NO-GO residual回収は回数無制限） |
| A2-c | production: `src/runtime/domain_store_d3s4.{h,c}` 新設 + **`src/runtime/domain_store_scanner.{h,c}` のS4結線**（Sol high P0-2: kind、context union、S4 forward decl、result **+2 fields**（offsets 52/53）、begin bind、internal hook/H2 dispatch、finalize/deferred disposition、abort無出力、cleanup/context zero）。scanner/result専用unit tests。CMake/private sources登録 | build+単体green + Grokレビュー |
| A2-d | production bridge（emit-c-fixture + 2-lane + count drift RED + freshness + **field-for-field完全比較**: 全checkpoint + 全Port event + request key + result全field; unknown scope/silent skip RED; Sol high P1-5） | bridge全green + Sol xhigh境界レビュー |
| A2-e | 統合QA（全CTest 通常/ASan+UBSan、strict warnings、ESP-IDF target build、context/outer静的assert、result offset/size assert）→ 受入証拠 → 日本語commit/PR/CI/merge/README/push | CI green + P0/P1=0 |

## 3. 編集範囲（Sol high P0-2/P2-1反映）

新規: `tools/domain_scan_crossrow_d3s4_vector_gen.py` / `src/runtime/domain_store_d3s4.{h,c}` / `tests/runtime/domain_store_d3s4_test.c` / `tests/runtime/domain_store_scanner_crossrow_d3s4_oracle_bridge_test.c`。
変更:
- `src/runtime/domain_store_scanner.h`（S4 kind/context union/forward decl/result 2 fields）/ `domain_store_scanner.c`（alias、begin bind、hook/H2 dispatch、finalize/deferred disposition、abort、cleanup/context zero）
- `spec/vectors/domain-scan-crossrow-v1.json`（append-only; 280 object authority不変）
- CMake: `cmake/ninlil_runtime_private_sources.cmake`（通常/VLA両list :11-33,58-64）、`tests/cmake/private_subproject/CMakeLists.txt`（source count/allowlist :74-129）、`CMakeLists.txt`（duplicate denylist :738、unit :1370-1395系、oracle check/self-test/fixture/bridge/freshness :1898-1962系）。ESP-IDF componentはshared list取込みのため直接編集不要
- current status更新（実装完了時のみ; §18.15本文不変）: `docs/17` global non-claim(:2296)、§18.2 S3/S4 rows(:2353-2355)、README、review ledger、docs/work台帳
禁止: §18.15本文変更、既存d3s1/s2/s3経路の弱化、public ABI変更、application-specific語彙、S4 context 949/960超、GCC非互換密集1行スタイル（A1 CI教訓）。

## 4. 役割

A2-a/a2/b oracleはQwen実装 + Fable契約突き合わせ + Sol high段階レビュー。A2-c/dはQwen + Grok diffレビュー + Sol xhigh境界レビュー。

## 5. 受入条件（最終; Sol high P1-4/P1-5/P1-6反映）

1. oracle `check` green（vector_count = 280 + suffix_N; A2-bで確定しpin）+ permanent RED self-test matrix + CLI fail-closed matrix。
2. prefix authority: first-280 full-object equality + format/count/content SHA/raw SHA pin + fail-closed（duplicate ID/非決定/malformed）。
3. coverage matrix **26/26**（§18.15.15 positive 11 + negative/mutation 15）green。
4. bridge: 全production vectorで**checkpoint全field + Port event全field + request key + result全field完全一致**、unknown scope/count drift/silent skip RED、freshness green。
5. get-budget: vectorごとのexact get-count一致 + quota=1 no-reissue検査。
6. result/publication: field offsets 52/53静的assert、host size/alignment、target `sizeof<=64`、abort無出力、whole-result poison不変（abort/cleanup failure/alias/incomplete finalize）、disposition sample→cleanup→single copy→context zero順序のテスト。
7. memory boundary: S4 949/960、S1+S2+S4 10112（packed 10060/10064）、full 10880（packed 10814/10816）、scanner 8192不変の静的assert。ESP task-stack high-water（finalize temp 64B込み）gate。
8. 実行拘束: 1 mode = 1 session = single READ_ONLY txn、mutation 0、各4 session独立baseline、をbridge/単体で検査。
9. 全CTest green（通常/ASan+UBSan）+ strict warnings 0 + ESP-IDF target build green + Linux/macOS CI green。
10. Sol high oracle GO + Sol xhigh境界GO + Grok P0/P1=0 + build provenance（A1形式）。

## 6. レビュー履歴

| 日時 | レビュア | 結果 |
| --- | --- | --- |
| 2026-07-21 | Codex Sol high(rev1) | **NO-GO** P0=2（all-old/mixed受理の凍結違反 / scanner結線欠落）P1=6 P2=1 |
| 2026-07-21 | rev2(本書) | 全P0/P1/P2反映（受理集合修正、scanner編集範囲、authority全域、§18.15.15 catalog 26項目、独立ゲート群A2-a2新設、prefix authority pin方式、bridge field-for-field、get-budget/result/memory受入条件、CMake/current-status列挙） |
