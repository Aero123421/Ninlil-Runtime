# 2026-08-12 OSS review: CMake test authority split

## 対象と事前に固定した境界

OR-23（top-level `CMakeLists.txt` の大半が test 登録）を、次の制約で閉じる。

- production option、policy、installable target、package/install 定義は top-level に残す。
- `NINLIL_BUILD_TESTS` の既存条件、directory scope、test 名、command、property、
  timeout、fixture/dependency を変えない。
- 新しい登録 framework や function wrapper は作らず、既存 CMake authority 境界へ
  tests-only block を機械分離する。
- default と全 private feature profile の CTest JSON を分離前後で比較する。
- public header、ABI、wire、storage、protocol semantics、maturity claim は変更しない。

作業開始時の fresh audit では `CMakeLists.txt` は 7,766 行、末尾の
`if(NINLIL_BUILD_TESTS)` block は 1,284--7,766 行の 6,483 行（83.5%）で、
`add_test` は 379 箇所だった。production/package authority は 1--1,283 行に
収まっていた。

## 変更

- tests-only block を `cmake/ninlil_ctest.cmake` へ同一 directory scope のまま移し、
  top-level は既存の `if(NINLIL_BUILD_TESTS)` からこの file を include するだけにした。
- test 登録を静的検査していた既存 gate は、production evidence は top-level、
  test-registration evidence は新 authority を読むように更新した。
- ESP component packaging gate の shell token 検査は、builtin `source` と
  `--only-source` option を区別する境界へ狭め、正負 self-test を追加した。
- OR-19 の layering gate を、新 authorityへ
  `layering_invariant_gate` / `layering_invariant_gate_self_test` として登録した。
  両方とも Python3 を使い、`TIMEOUT 30` とした。これは依頼された意図的な +2 test
  であり、既存 roster の意味変更ではない。
- OR-20 の installable Host Runtime 縮小後も古い期待を持っていた R7 T1/T1b
  tests-OFF packaging gate を同期した。明示 build する private archive では対象 object
  exact-once と private API exact-set を維持し、installed Runtime では対象 object/API
  zero を正例、再混入を負例にした。

最終的な top-level は1,300行未満まで縮小し、production authorityは移動していない。

## CTest semantic comparison

CTest `--show-only=json-v1` から、CMake file 移動により必ず変わる backtrace だけを除外し、
test の順序、名前、command、全 property を比較した。

| profile | 分離前 | 分離直後 | 結果 |
| --- | ---: | ---: | --- |
| default | 442 | 442 | semantic exact |
| all-private | 526（disabled 16） | 526（disabled 16） | semantic exact |

layering gate 登録後は default 444、all-private 528（disabled 16）。追加した 2 test を
除く既存 roster は上表の baseline と semantic exact で、追加 test の command は
それぞれ `check` / `self-test`。初回分離時のtimeoutは双方30秒で、後続のmutation
self-test拡張後はcheck 30秒 / self-test 180秒へ調整した。

all-private profile は Domain Schema 1、private Wi-Fi、private Fabric、R7 FRAG、RRMP、
MFDT を ON にし、unpinned Host OpenSSL を LAB 用に許可した構成で比較した。

## 検証

| 検証 | 結果 |
| --- | --- |
| default configure / all-target build | PASS（fresh 816/816、最終増分 108/108） |
| default smoke / docs / fuzz-seed / layering focused set | 7/7 PASS |
| all-private configure + build fixture / coexistence probe | 2/2 PASS |
| authority 参照を更新した focused gate 群 | 33/33 PASS |
| layering invariant check / self-test | 2/2 PASS |
| R7 T1/T1b tests-OFF packaging check / self-test | 4/4 PASS |
| fresh Release `NINLIL_BUILD_TESTS=OFF` | build 64/64 PASS、CTest `Total Tests: 0` |
| R7 T1/T1b private archive | wire object exact once + 8 API、binding object exact once + 6 API |
| R7 T1/T1b installed Runtime | private object 0、private family symbol 0、再混入 mutation RED |
| `git diff --check` | PASS |

広域 gate sweep で見つかった同時進行 MFDT 差分のin-memory tagは、wire/storage
magicと誤認されない非ASCII末尾値へ修正した。tests-only CMake移動で新たに走査対象へ
入った非magic token `TRUE` / `WRAP` は、移動先pathとexact countだけをregistryの
explicit exclusionへ同期した。protocol magic check と20変異self-test、Production
Attachment Python/Node/C11/freshness focused setはその後PASSした。

後続OR-04 trancheが追加したfuzzer tests-OFF negative CTestは、このOR-23の既存
roster比較後に意図的に加わった別証拠であり、上記442/526の分離前後同値性を変更しない。
後続OR-21 trancheのR7 caller-owned state testも同様に意図的な追加である。統合後の
現行fresh snapshotはdefault 448、all-private 535（disabled 21）で、baseline既存rosterは
引き続きsemantic exactである。分離後の意図的増分は、layering check/self-test 2件、
fuzzer tests-OFF configure負例1件、R7 owner 1件、RRMP serial-owner 1件、MFDT owner-state
check/self-test 2件である。追加のdisabled 5件は、Domain Schema 1
public Runtime readinessが未昇格のall-private構成で公開Runtime create成功を前提にした
`composition_v1_{create,namespace,lifecycle}`と
`mfdt_v1_runtime_{owner,sidecar_fault}_private`を誤実行していた配線漏れの修正である。
Domain-OFF companionを実行authorityとし、all-private側のcompile/linkは維持する。

並列CTestで同じNinja treeを更新する全build testには、単一の
`ninlil_ctest_build_tree` resource lockを付けた。これによりfixture同士が同時に
`cmake --build`を実行してNinja manifest/archiveを競合させる経路を閉じる一方、
実行test本体の並列性は維持する。

この記録は local software verification の範囲であり、remote CI、物理 HIL、RF soak、
release readiness を主張しない。
