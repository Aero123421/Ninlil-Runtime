# Host all-private CI false-green repair

状態: **Host software verified（normal + ASan/UBSan）**。物理HIL、RF、
実device、power-cutは **NOT_RUN**。

実行日: 2026-07-30 JST

## 目的

従来のHost completion CIは、6 private featureをconfigureしていても、実際には
手選択したWi-Fi + Fabric + RRMP + MFDT sourceだけをshellから直接compileしていた。
Domain Schema 1とR7 FRAGを含むproduction targetの同時build/linkを証明できず、
configure成功をall-private統合完了へ読み替えられるP1 false-greenだった。

`docs/07-testing-and-quality.md`へ先に受入境界を追加し、その後CMake、CTest、
CI、Host fixtureを修正した。

## 証拠の分離

今回のHost software evidenceは次の3層を混同しない。

1. **all-private aggregate build**
   - Domain Schema 1、Fabric、Wi-Fi、R7 FRAG、RRMP、MFDTのexact 6 featureを
     同じCMake treeでONにする。
   - production-private archive/objectと最終test executableを実際に
     compile/linkする。
2. **one-process coexistence probe**
   - CMakeがlinkした1 processから6 featureそれぞれのproduction live callを
     実行する。
   - これは同時共存、link、個別live-callの証拠であり、6 feature間の
     canonical cross-feature E2Eは**主張しない**。
3. **canonical actual E2E**
   - Foundation owner-planeからFabric canonical NFL1へ到達する
     `runtime_fabric_actual_e2e`、
     `multi_service_node_host_actual_e2e`、
     `mfdt_v1_fabric_actual_e2e`をbuild/runする。
   - Domain public Runtime readinessが未昇格のため、all-private treeでは同じ
     actual executableのcompile/linkまでを行い、3 CTestは明示的に
     `DISABLED`とする。実行はDomain OFF、他5 feature ONのcompanion profileが
     所有する。

`tests/support/host_completion_wire.c`を使うmulti-process scenarioは
test-only transport/restart fixtureであり、canonical owner-plane completion
または6 feature cross-feature E2Eのauthorityではない。Wi-Fi、R7 FRAG、
RRMP等、canonical actual pathへ接続していないedgeも接続済みと主張しない。

## 実装

- `CMakeLists.txt`
  - exact 6-feature条件の
    `host_completion_all_private_build` aggregateを追加した。
  - `ninlil_runtime_private`、Wi-Fi、R7 FRAG、coexistence probe、
    transport fixtureに加え、canonical actual executableも依存targetとして
    buildする。
  - aggregate build fixture、coexistence probe、transport positive、
    negative self-testをCTest登録した。
  - 6 featureの1つでもOFFならall-private Host testを登録しない。
- `tests/host/host_completion_all_private_coexistence_probe.c`
  - Domain startup T0、Fabric workspace partition、Wi-Fi NWB1 round-trip、
    R7 FRAG plan、RRMP owner/Fabric path、MFDT maximum geometryを1 processで
    production live-callする。
  - final markerに
    `canonical_cross_feature_e2e=NOT_CLAIMED physical_hil=NOT_RUN`を含める。
- `tests/host/host_completion_transport_fixture_e2e.c`
  - 旧integrated fixtureをtest-only transport/restart fixtureとして改名し、
    claim boundaryをsource上でも明示した。
- `tools/host_completion_integrated_e2e.sh`
  - source listのdirect compileを廃止した。
  - CMake-built driverとcoexistence probeを必須引数として受け取る。
  - marker、全role終了、sanitizer診断、positive/negative fail-closed性を検査する。
- `.github/workflows/ci.yml`
  - all-private aggregateをnormal/ASanで明示buildする。
  - actual E2Eのexact 3本だけがall-private treeでDomain-readiness
    `DISABLED`であることをCTest JSONで検査する。
  - Domain-OFF companionでexact 3本がenabledかつpassすることをnormal/ASanで
    検査する。
  - default-OFF、MFDT-only、6機能中5機能treeの誤登録を拒否する。

MFDT actual scenarioはdurable session generation `7`を使用し、terminal NM30の
time anchorが0にならないようdeterministic test clockを1000 ms進める。
NRC1は任意のnon-zero `uint32_t`初期generationとexact successorを受理し、
fixture都合でgenerationを1へ弱めていない。

## Local verification

### Normal all-private

構成:

```text
build/codex-p1-final-all-private-normal
Domain/Fabric/Wi-Fi/R7 FRAG/RRMP/MFDT = ON
```

結果:

```text
host_completion_all_private_build: PASS (157/157 build steps)
canonical actual executable: compile/link PASS
canonical actual registry: exact 3, Domain-readiness DISABLED
host completion focused CTest: 4/4 PASS
```

4 CTestはaggregate build fixture、one-process coexistence probe、
transport fixture positive、transport fixture negative self-testである。

### Normal canonical companion

構成:

```text
build/codex-p1-final-canonical-normal
Domain = OFF
Fabric/Wi-Fi/R7 FRAG/RRMP/MFDT = ON
```

結果:

```text
canonical actual registry: exact 3, enabled
runtime_fabric_actual_e2e: PASS
multi_service_node_host_actual_e2e: PASS
mfdt_v1_fabric_actual_e2e: PASS
CTest: 3/3 PASS
```

3つのCTest名は同じactual executableのcomplete scenario setを実行するaliasである。

### ASan/UBSan

```text
build/codex-p1-final-all-private-asan
  aggregate build: PASS (157/157)
  canonical actual registry: exact 3, Domain-readiness DISABLED
  focused CTest: 4/4 PASS

build/codex-p1-final-canonical-asan
  canonical actual executable: compile/link PASS
  canonical actual registry: exact 3, enabled
  canonical actual CTest: 3/3 PASS
```

macOS AppleClangのAddressSanitizerはLeakSanitizerを未対応として
`detect_leaks=1`を即時拒否するため、local ASan実行は
`detect_leaks=0:halt_on_error=1:abort_on_error=1`とした。UBSanは
`halt_on_error=1:print_stacktrace=1`である。LeakSanitizer evidenceは主張しない。
Linux CIも既存どおり`detect_leaks=0`を明示する。

### False-green mutation

fresh configureのCTest JSONを検査した。

```text
default-OFF: all-private Host evidence absent
MFDT-only: all-private Host evidence absent
Domain/Fabric/Wi-Fi/R7 FRAG/RRMP ON + MFDT OFF:
  all-private Host evidence absent
  complete all-private traceability profile absent
```

## Traceability同期

最終検証時、並行するpublic ABI作業によって`docs/12-foundation-abi.md`が更新中で、
`requirements-traceability-coverage.json`のbyte drift fenceが意図どおり
fail-closedになった。共有仕様を途中状態でmaterializeしないため、このlaneでは
manifestを更新していない。public ABI lane安定後にauthorityを再materializeし、
次を再実行して結果を追記する。

```text
python3 tools/traceability_complete_coverage_gate.py --self-test
python3 tools/traceability_complete_coverage_gate.py --check \
  --profile all-private=build/codex-p1-final-all-private-normal
```

## 既存reviewとの関係

`docs/reviews/2026-07-30-host-completion-integrated-e2e-review.md`は当時の
test-only transport fixture内のauthority/fail-closed性を確認した履歴として
保持する。その文書中の「integrated E2E」をall-private production build、
Domain/R7接続、またはFoundation canonical cross-feature completionの証明として
再利用してはならない。本記録がそのclaim boundaryと現行CI受入の正本である。

## Claim boundary

確定したのはHost normal + ASan/UBSan software evidenceだけである。
ESP32-S3実機、physical HIL、RF、real AP、secure element、power-cut、remote CIは
今回実行していないため、すべて **NOT_RUN**。外部AI CLI
（Grok Build、Claude/Fable、Qwen、Cursor、opencode等）は使用していない。
