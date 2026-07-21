# D3-S3 R27回収トランチ — 受入証拠

作成: 2026-07-21 / Fable統合QA。計画: `2026-07-21-d3s3-r27-bridge-recovery-plan.md`(rev3; Sol high GO P0=0 P1=0 P2=0)。

## 実装

- 実装者: OpenCode `alibaba-token-plan/qwen3.8-max-preview`(2ラウンド)。
- 変更ファイル(pre-Qwen snapshot `/Users/dt/job/LoRa/ninlil-attic/2026-07-21-pre-qwen-snapshot.tar.gz` とのdiffで機械確認):
  - `src/runtime/domain_store_d3s3.c`(Qwen; 許可範囲)
  - `tests/runtime/domain_store_d3s3_test.c`(Qwen; エスカレーション承認後の追加範囲)
  - `docs/reviews/2026-07-20-d3s3-implementation-candidate.md` / `docs/work/*`(Fable; docs)
- スコープ逸脱: なし(共有fixtureヘッダ・spec JSON・tools・CMake・codec不変)。

## 修正前の失敗ID一覧(9 unique)

`D3S3_M27_EF_TERMINAL_ACTIVE_CORRUPT`(checkpoint lifecycle 3→期待0), `D3S3_M27_EF_NONTERM_RELEASED_CORRUPT`, `D3S3_M27_EF_DS_STATE_FAMILY_CORRUPT`, `D3S3_M27_EF_STATE_AVD_PVD_FOREIGN_CORRUPT`, `D3S3_M27_EF_SPOOL_PVD_FOREIGN_CORRUPT`, `D3S3_M27_EF_REV_MISMATCH_CORRUPT`, `D3S3_M27_EF_PARKED_ACTIVE_CORRUPT`, `D3S3_M27_EF_READY_PARKED_CORRUPT`, `D3S3_M27_EF_PARK_CAUSE_MISMATCH_CORRUPT`(各false-green)。

## 受入結果

| 条件 | 結果 |
| --- | --- |
| bridge | **green**: `domain_store_scanner_crossrow_d3s3_oracle_bridge OK (136 typed vectors; production=135 formal_precheck=1)` exit 0(Qwen報告+Fable独立再実行) |
| fixture_freshness | green(全CTest内) |
| 全CTest 通常build | **230/230 green**(Fable独立実行 `ctest --test-dir build-root-d3s3 -j 8` exit 0, 96.27s) |
| 全CTest ASan/UBSan | **226/226 green**(`build-root-d3s3-san`, 107.34s; sanitizer構成でのテスト数は226) |
| strict warnings | 0(qa-build.log grep) |
| vector JSON SHA-256 | `1506f43229b27254e70cc8fc54faa039711007924d015c451a3fd23114d59fe2`(不変確認) |
| 無後退個別確認 | bridge 135 production全green内で EVENTFACT_LIVE_OK系 / HISTORICAL_RECEIPT_OK / HISTORICAL_DISCARD_OK / DS系 / fault precedence(1GET/2GET) / missing-only-CORRUPT を含む126既green全維持(bridge出力=全vector visit・silent skip RED設計) |

## build provenance

| 項目 | 値 |
| --- | --- |
| build dir | `build-root-d3s3`(Debug)/ `build-root-d3s3-san`(NINLIL_ENABLE_SANITIZERS=ON) |
| HEAD | `39026aeb7415ada9654213332a087d388cab879e` |
| tracked diff sha256(`git diff HEAD \| shasum -a 256`) | `a4ed8320125c7a1b445929c4ac9fc9669d8aecb1716356ed8337913a2d50e8be` |
| untracked manifest sha256(`git ls-files --others --exclude-standard \| sort \| xargs shasum -a 256 \| shasum -a 256`) | `a13bdaa6dce7fbbfebf8e4c7efc070573ebf58a205517af07dd94cd279eb525d` |
| 生成fixture header sha256 | `c6d5fa38287aee56ed84df97863ce660807039bd3b9138e1cf8d36fb6f7f60cb` |
| compiler | Apple clang 21.0.0 (clang-2100.1.1.101), /usr/bin/cc |

(注: 上記diff/manifest hashはレビュー時点の作業状態のもの。commit確定後は commit hash が正となる。)

## レビュー

| レビュア | 結果 |
| --- | --- |
| Grok Build grok-4.5(diff) | **P0=0 P1=0 P2=3**(P2: 単体CORRUPT網羅が2 caseのみでbridge依存 / missing-spool testのSTATE未patch明示化 / コメント番号のoracle対応併記) |
| Codex GPT-5.6 Sol xhigh(境界) | **GO P0=0 P1=0 P2=1**(P2: generator内コメント2箇所が`expected_owner_pvd` slotと誤記; 実map/実装は`view_a_key_digest`で正)。閉積の意味的完全一致・観測契約一致・slot衝突なし・旧ILLEGAL_CARRIER検査の完全包摂・fixture patchのfalse-passなしを個別確認 |

## 残課題(P2 backlog; 本トランチmerge非阻止)

1. 単体テストへ代表cross-row CORRUPT(family/rev等)を1-2本追加(Grok P2-1)。
2. missing-spool testのSTATE patch明示化(Grok P2-2)。
3. production/generatorコメントの相互参照整備(Grok P2-3 + Sol xhigh P2; generatorコメント修正はoracle改版タイミングに同乗)。
