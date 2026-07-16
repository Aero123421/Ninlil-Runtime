# 07. Testing and Quality

状態: Normative Foundation quality baseline（後続milestone gateは条件付き）<br>
対象: Foundation以降の全release

## Quality model

Ninlilの品質は「unit testが通る」だけでは成立しません。要件、状態機械、fault、hardware、release artifactを追跡します。

M0 specification baselineでは、12・13章の`file + heading`と14章のconformance vector IDをtemporary requirement identityとします。`requirements-traceability.yaml`はM1a PR 1で作成を開始し、PR 3 gateまでに12〜14章のnormative requirementと本章のinvariantをstable requirement IDへ対応付けます。対応が完全でないbuildはM1a conformance/release合格を名乗れません。00〜11章のarchitecture/policy requirementはpublic alpha前にstable IDへ移行します。

```text
requirement ID
-> unit/model/conformance test ID
-> supported profile
-> CI or release gate
-> evidence artifact
```

Requirementを削除・弱化する変更は、testだけを削除して通してはいけません。仕様変更理由とcompatibility impactを必要とします。

## Test layers

1. pure unit test
2. public C API compile/conformance
3. cross-language golden vector
4. state model/property test
5. parser/stateful fuzz
6. deterministic simulator
7. storage/power-loss fault injection
8. compatibility matrix
9. target firmware build
10. hardware-in-the-loop (HIL)
11. RF/load/soak
12. compliance/security evidence test
13. example/docs smoke
14. reproducible release artifact/SBOM check

上位層を下位層で代替しません。SimulatorだけでRF性能や法規適合を証明したと表現してはいけません。

## Deterministic simulator

SimulatorはRuntime roleではなく、Controller/Endpoint Runtimeを駆動する外部harnessです。Virtual timeとexplicit seedを使用し、失敗時は次を出力します。

- seed
- scenario/profile revision
- event trace
- relevant storage snapshots
- invariant violation
- minimal reproduction command

必須fault:

- loss、duplicate、reorder、corruption、delay
- one-way / two-way partition
- carrier busy / send denied
- parent loss / route change
- sleepy receive window miss
- Controller / Cell Agent / Endpoint restart
- process crash at named storage boundary
- storage full、write fail、torn write、corruption
- clock jump / rollback / trust loss
- late Receipt
- cancelとapplication effectの競合
- idempotency key conflict
- queue/resource exhaustion
- compliance permit denial

Random faultだけでなく、全named crash boundaryをsystematicに走査します。

## 常時検査するinvariant

- `NIN-INV-001`: required Receipt未到達で`SATISFIED`にならない。
- `NIN-INV-002`: terminal Outcomeは書き換わらない。
- `NIN-INV-003`: admitted transactionにはdurable roster、required assessmentのpass、authority-owned local resourceの有限reservationがある。
- `NIN-INV-004`: transaction IDはattempt、retry、restart、path変更を跨いで不変。
- `NIN-INV-005`: logical retryではattempt IDを更新する。Physical frame nonceはM1a typed bearerの対象外で、M5 protected wireから再送ごとに更新する。同じattemptのobservation前crash replayは12〜14章の例外規則に従いattempt IDを維持する。
- `NIN-INV-006`: EventFactをsilent drop/replaceしない。
- `NIN-INV-007`: durable commit前に`DURABLY_RECORDED`を発行しない。
- `NIN-INV-008`: application result cache commit前に`APPLIED`を発行しない。
- `NIN-INV-009`: old generationを新しいstateとして適用しない。
- `NIN-INV-010`: queue、retry、dedup、reassembly、journalはprofile上限を超えない。
- `NIN-INV-011`: rejected/counter-offered submissionをdelivery成功率の分母から隠さない。
- `NIN-INV-012`: permitなしphysical TXはゼロ。
- `NIN-INV-013`: old membership/attachment epochのframeを新epochで受理しない。
- `NIN-INV-014`: broadcast TXをtarget別application evidenceとして扱わない。

## Foundation conformance suite

### Generic DesiredStateCommand

1. concrete targetへabsolute stateを提出する。
2. submission、roster、reservationをatomic commitする。
3. simulated bearerでduplicateを注入する。
4. Endpoint Service Adapterがeffectを適用する。
5. result cache commit後に`APPLIED`を返す。
6. Controllerはrequired evidence到達後だけ`SATISFIED`にする。
7. Controller/Endpointを各crash boundaryで再起動し、二重effectまたはunknown境界がcontractどおりであることを確認する。

### Generic EventFact

1. Endpointが有効なorigin grant下でeventをdurable local admissionする。
2. duplicate/loss/reorderを注入する。
3. Controllerがevent IDとdigestをatomic dedup/storeする。
4. commit後だけ`DURABLY_RECORDED`を返す。
5. Endpointはcustody/release policyに従ってspoolを解放する。
6. 全crash boundaryでeventのsilent lossと重複business recordがゼロであることを確認する。

### API contract

- wrong thread
- callback re-entry
- null/invalid argument
- small output buffer + required size
- old/new `struct_size`
- duplicate service registration same/different digest
- same idempotency key same/different digest
- counter-offer予約値と`offer_accept`がM1aでunsupportedになること。expiry/acceptance raceはM2から必須
- cancel before dispatch / in-flight / after effect
- restart後のtransaction list/query

## Storage crash matrix

各atomic groupについて、次の全境界でcrashします。

- before begin
- after each put/delete
- before commit
- during backend commit
- immediately after commit acknowledgement

Recovery後の許可状態は「全recordなし」または「全recordあり」だけです。部分roster、reservationなしadmitted、receiptだけ存在する状態を許しません。

## Fuzz targets

- public binary decoder/encoder
- simulated bearer framing
- storage migration reader
- ServiceDescriptor/capability/profile loader
- receipt/evidence parser
- destination/target roster input
- future Join and transfer/reassembly parser

Fuzz inputでunbounded allocation、hang、secret log、panic、undefined behaviorを起こしてはいけません。

## CI gates

### Pull request

- portable unit/conformance tests
- public C header compile smoke: C11 and C++17 consumer
- golden vectors
- deterministic simulator: fixed regression set + 100 seeds
- all Foundation named crash boundaries
- ASan/UBSan on POSIX
- each exposed parser 60-second fuzz smoke
- docs link/example smoke
- legacy regression tests affected by the diff

### Nightly

- 10,000 simulator seeds
- each exposed parser 30-minute fuzz
- TSan where supported
- storage corruption/migration matrix
- mixed-version matrix
- deterministic replay of all retained failing seeds

### Firmware/radio change

- pinned ESP-IDF target build
- HIL smoke
- profile/TxPermit path test
- actual radio setting measurement where the change affects PHY/compliance

### M3-prep / M3-basic packaging CI（host と分離）

M3 complete 前でも、component packaging と basic platform adapters の回帰を次で防ぎます（[18章](18-m3-prep-esp-idf-component.md)、[20章](20-m3-basic-esp-idf-platform-adapters.md)）:

- host CTest: `esp_idf_component_packaging_gate`（portable / port source authority 分離、pin 一致、no GLOB、portable に ESP-IDF include なし、port-owned headers、smoke が 3 adapter を include）
- host CTest: `esp_idf_port_logic`（clock/entropy/execution の invalid argument / boundary / entropy singleton lifecycle）
- 分離 workflow `.github/workflows/esp-idf.yml`: 公式 image `espressif/idf:<ESP_IDF_VERSION>` で **esp32s3 smoke app の compile/link build**（`idf.py set-target esp32s3 build`）。**device 上の実行や HIL は含まない**
- host `ci.yml` は ESP-IDF を install せず、従来の GCC/Clang CTest のみ
- 実機/HIL/on-target runtime smoke は **未実証**。CI が証明するのは target firmware image の **build** まで

### M3 control framing slice

[19章](19-m3-control-byte-stream-framing.md) の production-candidate private `NCG1` codec は次を host CTest で証明します（M3 complete の代替ではない）:

- `control_frame_codec`: encode/decode round-trip、overflow/truncation、手書き boundary/reject、noise resync、concat、1-byte incremental、guard 境界（noise2087+empty26）、alias（payload_storage×out_*）
- `control_frame_vector_oracle`: independent Python `check`（JSON ≡ generator、mutation recipe 適用 + 独立 decode）
- `control_frame_vector_gen_self_test`: recipe/expected/operator 改変が fail することを自己検査
- `control_frame_vector_oracle_bridge`: `emit-c-fixture` が **適用済み** golden+negative bytes と `expected_result` を deterministic header へ生成し、**production C** `ninlil_model_control_frame_decode` が全件 loop で一致（JSON/recipe 変更が C に追随しない false-pass を防ぐ）
- `control_frame_vector_fixture_freshness`: emit 二重実行 determinism + build fixture freshness

### Release candidate

- all PR/nightly gates green on release commit
- 24-hour soak for supported field profile
- zero unresolved mandatory test skip
- reproducible build check
- SBOM and third-party license report
- compatibility matrix, CHANGELOG, migration guide
- signed artifacts when release signing is introduced

Release candidate gateは、そのreleaseが実装するfeatureにだけ適用します。M1aではwire、Cell Agent、physical airtime、field soak、production credentialを`not_applicable_until`としてgate matrixに記録し、skipによるpassとは区別します。

GitHub Actionsのbilling停止、runner不足、manual skip、flaky rerunはpassとして扱いません。

## Coverage

Foundationの初期gate:

- portable core line coverage 80%以上
- transaction、storage、receipt/outcome state machine branch coverage 90%以上
- uncovered error branchをrelease noteで正当化する運用は禁止し、testか非到達証明を必要とする

Coverageはinvariant、fault injection、HILを代替しません。Public alpha前にmutation testをnightlyへ追加し、thresholdは実測後に固定します。

## Performance and SLO profile

性能はversioned scenario fileで宣言します。

```text
profile ID / revision
hardware / firmware / regulatory profile
node count and role mix
service mix
submitted rate / burst / payload distribution
sleep schedule
required evidence / deadline
fault and RF environment
run duration and minimum admitted target count
```

将来の容量profile候補:

```text
NINLIL-FIELD-50-A
nodes: 50
offered logical requests: aggregate 20 / 10 seconds
traffic mix: scenario fileで固定
minimum run: 24 hours and 10,000 admitted target deliveries
```

Reportは次を分けます。

- submitted
- admitted ready / scheduled
- counter-offered
- rejected by reason
- coalesced/superseded
- satisfied within deadline
- expired / failed / unknown
- late evidence
- duplicate physical delivery / duplicate application effect
- airtime / legal budget / queue high-water

KGuardの5秒/99.9%等は`KGUARD-PILOT-*`profileで定義し、Ninlil全体の無条件保証にしません。

## Hardware exit gate候補

最初の3台KGuard HILでは、Display commandとDurable Eventを各1,000件実行し、Controller/Endpoint再起動を含めます。合格条件:

- false success 0
- contract外のduplicate application effect 0
- durable EventFact silent loss 0
- terminal Outcome reversal 0
- permit bypass 0
- 全failureをreason付きで説明可能

RF性能・電池寿命・日本deployment complianceは、この3台gateだけでは証明済みとしません。

## Contributor usability

- 実機なしでFoundation conformanceを実行できる。
- failing seedを1 commandで再現できる。
- generic exampleをKGuardなしでbuild/runできる。
- optional HILがないだけでportable Coreへのcontributionを拒否しない。
- hardware-specific changeだけがhardware gateを要求する。
