# 2026-08-11 OSSレビュー first aid

日付: 2026-08-12

## 対象

入力reviewの対象commitは`9cc907fe3a384aba9bf0e984b62fa55fa1207f3f`。
レビューで再現された正面玄関の問題だけを先に閉じた。READMEはfull ASan/UBSan
CTestを「5分 quickstart」としていた。また、通常のtests-ON configureはNodeを必須に
するのに、必要version・対処法・CI pin・依存台帳が無かった。protocol magicの
self-testはsource treeへmutantを書き、並列実行と中断後のcheckoutを壊し得た。

本変更はpublic ABI、wire、storage、Runtime機能状態を変更しない。

## 変更

- README入口を通常Debugのfocused `v1_integration_gate_e2e` 1件へ変更し、full
  CTestとClang sanitizerを別手順・別claimにした。full CTest前には全targetをbuildする。
- Node.js >=18をREADME / CONTRIBUTING / CMakeへ固定した。不在・実行不能・旧version
  は、install方法と`NINLIL_BUILD_TESTS=OFF`代替を示してconfigure時に拒否する。
- tests-ONまたはNode authorityを実行するCI 21 jobとrelease verifyで、commit固定の
  `actions/setup-node`とNode 22.18.0を使う。release workflow identity gateもAction
  commit、job集合、version、`check-latest=false`を検査する。
- Nodeをdependency inventory、notices、notice gate、release SPDX SBOM入力へ
  `host_tooling`として登録した。SPDXはNodeを`APPLICATION`かつ
  `Node BUILD_TOOL_OF Ninlil Runtime`として表し、library/runtime dependencyへ偽装しない。
  npm packageやproduction link依存は追加していない。
- 公開Runtime APIのservice登録、submit、bounded step、Receipt反映後query、同じ永続
  providerでのrestart/queryを示すC11 exampleと、MQTT-SN / LoRaWAN / CoAP / Zenohとの
  短い非代替関係表をREADMEへ追加した。
- `tmp-controller*`、`tmp-install*`、`tmp-all-private*`をignoreした。
- protocol magic self-testはscan対象だけを一度unique temporary repositoryへコピーし、
  mutantをその中だけで生成する。source treeへのwriteとprocess間の共有mutant pathを
  無くし、旧source-tree mutation用のCTest `RESOURCE_LOCK`も削除した。
- Traceability Coverage V2をRegistration Coverage V2へ改称した。これはNormative
  unit、enabled CTest名、source anchorの登録対応を検査するだけで、CTest実行結果や
  assertion強度の証明ではないことをREADME・Normative quality文書・tool出力へ固定した。

## ローカル検証

| 検証 | 結果 |
| --- | --- |
| Nodeあり通常CMake configure | PASS（Node v22.23.1） |
| NodeなしCMake configure | PASS: 対処法つき`Node.js >=18` FATAL_ERROR |
| README focused build + `v1_integration_gate_e2e` | 1/1 PASS |
| README Runtime C例の抽出・strict C11 compile | PASS |
| protocol magic check/self-test | PASS（20 mutations） |
| protocol magic self-test 8 process同時実行 | 8/8 PASS、source mutant残留0 |
| traceability legacy + registration V2 | 4/4 PASS |
| third-party inventory/notice check+self-test | PASS |
| release SPDX SBOM self-test（Node purpose/relation負例を含む） | PASS |
| release workflow identity check+self-test | PASS |
| release archive/distribution check+self-test | PASS |
| workflow YAML parse / actionlint 1.7.12 | PASS |
| Markdown link check+self-test | PASS |
| `git diff --check` | PASS |
| 独立最終review | **GO — P0=0 / P1=0 / P2=0** |

## 非claimと後続

full CTest、sanitizer全suite、remote CI、release support、ESP実行、HILを本変更の
結果としてはclaimしない。fuzz harness、非gating coverage、CodeQL、ABI ILP32 golden、
compatibility matrixの公開3 package、layering gate、copyright/DCOは、それぞれ正本と
受入を持つ後続trancheとして残す。
