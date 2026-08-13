# OSS review: README / build-option UX tranche

日付: 2026-08-12

## 目的

OSS利用者の最初の入口を短くし、状態根拠、英語overview、CMake設定面、履歴文書の境界を
過剰な新設計なしで明確にする。実装・互換性状態・法務状態は昇格しない。

## 変更

- `README.md`の長いV1 software evidence、巨大な次gate表、完了順序、検証区分を
  `docs/status.md`へ分離した。READMEには今日使えるHost範囲、未証明の実機／release範囲、
  既存compatibility gateが読むcompact stateを残した。
- 非規範的な`README.en.md`を追加し、日本語仕様／Accepted ADRが正本であることと
  2026-08-12時点のtranslation statusを明記した。日本語READMEと相互linkした。
- CMakeの21 `option()`と2 typed cache variableを一表にした`docs/build-options.md`を追加した。
  `tools/build_options_docs_gate.py`でsource集合と文書の23行を照合し、CTestへ登録した。
  並行trancheで追加されたABI golden missing用opt-inも、既定OFF、通常非推奨、CI/release禁止の
  保守用escape hatchとして同じ表へ同期した。
  後続のdecoder libFuzzer opt-inもdefault-OFF/non-installedとして同じauthorityへ同期した。
- 既存のrole-neutral `examples/multi_service_node/`をV1 LAB例より先に案内した。新しいexampleや
  frameworkは追加していない。実行にはprivate Fabric gateが必要であることも明記した。
- 3つの`v1.0-lab-rc2`文書にHISTORICAL bannerと現行正本linkを追加した。旧CMake 3.16条件は
  履歴であり、現在は3.20以上であることを明記した。

## 検証

- `python3 tools/build_options_docs_gate.py check` — PASS（23 entries）
- `python3 tools/build_options_docs_gate.py self-test` — PASS（missing / extra / duplicateを拒否）
- `python3 tools/markdown_link_gate.py check --root .` — PASS
- `python3 tools/markdown_link_gate.py self-test` — PASS
- 同じlink checkerを`README.en.md`、`docs/status.md`、`docs/build-options.md`へ明示適用 — PASS
- `python3 tools/compatibility_matrix_gate.py check` / `self-test` — PASS
- README focused smokeのtarget buildと`v1_integration_gate_e2e` — PASS
- focused integration gateのSQLite/WAL/lock資源はbuild tree固有の
  `v1-integration-gate-work`で実行し、source rootを汚さず別buildと衝突しない。
- root-local DB/lock、ABI scratch、`.DS_Store`、`dist/`もexact root patternでignoreし、
  direct runの失敗後でもrelease/stagingへ混入させない。
- generic exampleの明示configure、target build、`multi_service_node_host_actual_e2e` — PASS

`--all-markdown`走査は、既存build treeとESP managed dependency内の外部／生成文書link 18件を
報告した。今回の新規文書ではなく、tracked gateと新規3文書の明示検査は合格している。

## 非主張・別tranche

- compatibility matrixのfeature追加、公開header API docs、ADR状態、copyright/SPDX/DCO、
  GitHub description/topics/badges/Discussions、全47文書へのtranslation metadataは変更していない。
- physical USB/RF、実AP、flash power-cut、soak、remote CI/releaseはこのtrancheで実行していない。
- `.DS_Store`と`dist/`の実体は変更せず、ignoreだけを追加した。commit/pushは行っていない。
