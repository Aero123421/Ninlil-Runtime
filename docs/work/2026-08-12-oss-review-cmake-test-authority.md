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

Tracked pre-split commit `b9e656f`のfresh auditでは`CMakeLists.txt`は7,695行だった。
以前記載した7,766行はuntracked intermediateの値で、再現可能な証拠ではないため撤回する。
split commit `7c68024`はtop-level 1,289行と`cmake/ninlil_ctest.cmake` 6,548行である。
同commitは他のOSS-review修正も含むため、`b9e656f..7c68024`全体のrosterがsemantic exact
だとは主張しない。split refactor単体は、tracked `b9e656f`からtests-only blockだけを
機械移動したisolated replayで検証する。

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

`b9e656f`の1261行目から末尾にある、exact marker
`if(NINLIL_BUILD_TESTS)\n    enable_testing()`で一意に特定したblockは6,435行、その内側の
tests-only payloadは6,433行（SHA-256 `87829c9b…`）、`add_test`は372件だった。
isolated replayでは、その内側をbyte-for-byteで新fileへ移し、元のblockを同じ条件の
`include(...)`へ置換した。top-levelは1,263行、tests fileは6,433行になった。

分離前後それぞれをfresh configureし、CTest `--show-only=json-v1`からfile移動で変わる
per-test backtraceだけを除外した。異なるtemporary rootによるsource/build absolute pathは
同じplaceholderへ置換し、testの順序、名前、command、propertyとその順序・値は保持した。

| profile | tracked pre-split | isolated split-only replay | 結果 |
| --- | ---: | ---: | --- |
| default | 432 | 432 | semantic exact |
| all-private | 516（disabled 16） | 516（disabled 16） | semantic exact |

normalized roster SHA-256はdefaultの両側が`efcfdc36…`、all-privateの両側が
`9e19b69b…`で一致した。

`7c68024`実commitはdefault 448、all-private 535（disabled 21）で、preとの差は
default +16、all-private +19に加え、同時に入ったtimeout/resource-lock/working-directory/
feature wiring変更を含む。これらをsplit-only equivalenceへ混ぜない。初回分離時の
layering timeoutは双方30秒で、後続のmutation self-test拡張後はcheck 30秒 /
self-test 180秒へ調整した。

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

後続OR-04 trancheが追加したfuzzer tests-OFF negative、OR-21のR7/RRMP/MFDT owner-state、
OR-22 epilogue gate、review provenance gateは、split-only replay後の別証拠である。最終
snapshotはdefault 452（disabled 0）、all-private 541（disabled 21）、tests-OFF 0である。
追加のdisabled 5件は、Domain Schema 1
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
