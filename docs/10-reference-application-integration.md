# 10. Reference Application Integration Profile

状態: Normative integration baseline<br>
対象: 製品・業務アプリケーションがNinlil Runtimeを利用する境界

## 原則

```text
Reference application / management
        |
        | Ninlil public API
        v
Ninlil Runtime
```

依存は一方向です。

- applicationはNinlil public APIを利用します。
- Ninlil Coreはapplication固有package・schemaをimportしません。
- schema、business rule、UI、SLO policyはapplication側に置きます。
- application固有enumをNinlil wire/coreへ追加しません。

## Legacy LinkOS Lab v1

旧検証資産を取り込む場合は **legacy LAB asset** として凍結します。

用途:

- 3台benchの再現
- AES-GCM cross-language golden fixture
- Pico UART applied behaviorの比較
- Leak NVS pending behaviorの比較
- SX1262 hardware adapterの選択的再検証

禁止:

- Legacy wireをNinlil Wire v1と呼ぶこと
- application enumを追加しながら汎用coreへ育てること
- legacy DB/NVS/API/CLIをNinlil public compatibilityにすること
- production key/profileとして使うこと

Ninlilへ再利用する部品は、public contractとtestを満たす形へ移植します。folder copyやnamespace置換だけで移しません。

## Mapping

| Reference application concept | Ninlil contract | Required evidence / rule |
| --- | --- | --- |
| 表示盤の絶対状態 | `DesiredStateCommand` | Pico/application反映後`APPLIED`。physical feedbackが追加された場合`VERIFIED` |
| 漏水/つまり等の発生・復旧transition | `EventFact` | Controller/application journal commit後`DURABLY_RECORDED` |
| 現在のoccupancy/個室bitmap | `LatestState` | replace key + monotonic generation。重要transitionは別EventFact |
| battery/device health snapshot | `LatestState` | coalesce可。履歴が必要ならMeasurementBatch |
| 温度/流量等の計測 | `MeasurementBatch` | batch/downsample/retention policy |
| 表示辞書、font、image、長文asset | `BoundedTransfer` | Wi-Fi/USB優先、全体digest後atomic handoff |
| calibration/policy/template revision | `ConfigRevision`候補 | stage/validate/commit/rollback |
| QR設置/移設/撤去 | Management lifecycle API | enrollment/binding/commission/drain/remove/reuse |

「漏水なら表示を使用不可にする」はNinlilの責務ではありません。application rule engineがEventFactを受け、別のDesiredStateCommandを生成します。

## Display flow

1. applicationがlogical installation mappingを提供し、Ninlil Controller resolverがconcrete device + binding epochへ固定する。
2. Desired absolute state、generation、idempotency key、deadline、required evidenceを提出する。
3. Ninlilがadmission結果を返す。
4. `ADMITTED_READY/SCHEDULED`でもapplication UIは「受付済み」であり「反映済み」と表示しない。
5. Endpoint Service AdapterがPicoへ適用する。
6. Picoの成功応答とpersistent result cache commit後だけ`APPLIED`。
7. application UIはtarget別Outcomeを表示する。

Group/all-display操作でも、logical successをbroadcast TXだけで確定しません。Required evidenceを要求するprofileではtarget rosterとtarget別Receiptが必要です。

applicationはNinlil transaction Outcomeとは別に、`全完了 / 一部完了 / 未達 / 結果不明`のaggregate viewを作ります。一部失敗時はtarget別一覧を表示し、失敗targetだけを新しいrosterとtransactionで再実行します。交換・撤去済みtargetを元transactionへ暗黙追加しません。

## Leak Event flow

1. battery endpointがphysical transitionを検出する。
2. application sensor adapterがstable event IDとpayloadを作る。
3. 有効なorigin grant下でNinlil Endpointが`NINLIL_NO_DEADLINE` EventFactをdurable local admissionする。
4. endpointはsleep/retry policyに従いspoolを保持する。
5. Controllerがevent identity/digest/payloadをapplication journalへatomic commitする。
6. commit後だけ`DURABLY_RECORDED` Receiptを返す。
7. endpointはcustody release policyに従いspoolを解放する。

同じcontactがactiveのままwakeするたび新eventを作りません。application schemaは`ACTIVE transition`、必要なperiodic reminder、`CLEAR transition`を区別します。

### Leak local admission failure

検知したこととEventFactをadmitできたことを分けます。Grant切れ、storage異常、spool full、profile不整合でlocal admissionできない場合、application sensor adapterは次を行います。

1. Ninlil成功Receiptを生成しない。
2. hardwareが許すlocal indication/interlockを直ちに実行する。
3. `OP_LOCAL_SAFETY` reasonと未admit transition countをbounded diagnosticへ残す。
4. raw contactの現在状態を維持し、次のservice/connection windowでreconciliationを試す。
5. field operatorへLED等の製品固有表示を出す。
6. spool解放のためのEventFact discardは、actor、理由、最終evidenceをapplication auditへ保存した明示操作だけ許可する。

Storage自体が故障している場合に「検知を保存済み」と表示しません。Product profileはLED pattern、local fail-safe、retry間隔、operator escalation時間を具体値で定めます。

## Application end-to-end evidence view

Ninlil Receiptとapplication/cloud processingを1つの成功にまとめません。

| Application表示段階 | 根拠 |
| --- | --- |
| endpoint受付/保存 | endpoint local admission record |
| 現場PC保存 | Controller/application journal commit後の`DURABLY_RECORDED` |
| application rule処理済み | rule engineの独立operation record |
| Display反映 | targetごとの`APPLIED` |
| 現在も目的状態 | LatestState/reconciliationのfresh evidence |
| cloud同期済み | cloud側commit/ack。Ninlil Receiptとは別 |

Displayの`APPLIED`は適用時点の証拠であり、再起動後も現在表示中であることを永久には保証しません。必要なserviceはperiodic reconciliationを要求します。

## Occupancy and toilet rows

横並びトイレの利用状況は、各sensor sampleを全てEventFactとして流しません。

- 現在状態: zone/toilet-row単位のLatestState bitmap
- 重要な利用可否transition: EventFact
- 生sample/距離/診断: LAN/Wi-FiのMeasurementBatchを優先
- 未送信のold bitmap: new generationでreplace
- reporting/analytics: application側で必要な粒度を保存

これにより利用者増加時も、古い現在状態が帯域を占有し続けません。

## Text and display asset

短いpreset/referenceはcompact schema IDで送ります。文字列/assetの優先順:

1. deviceに存在するpreset/template ID
2. versioned dictionary reference
3. small bounded delta
4. Wi-Fi/USB BoundedTransfer
5. LoRa fragmentation（後続profileで明示許可された場合だけ）

Safety EventFactをlarge transferと同じqueue/resource poolに置きません。

## QR lifecycle

QRはpublic hardware/device identityだけを持ち、secretを含みません。

### Install

1. scan device
2. choose/confirm site and logical installation
3. enroll membership
4. bind installation + binding epoch
5. attach/route/grant
6. application commissioning test
7. evidence後にapplication UIを「設置済み」へ変更

### Planned removal

1. scan/choose installation
2. inspect pending/unknown transactions
3. drain route/children
4. receive removal assessment
5. operator confirms unresolved impact if forced
6. revoke membership/binding
7. physical removal
8. cloud sync confirmationを別表示

application removal profileは作業期限、drain最大待機、assessment TTL、sleepy nodeのlast-seen許容age、未移行一覧、強制撤去承認者、撤去後reconcile/rollback期限を必須fieldにします。期限切れassessmentで物理撤去を許可しません。

### Reuse at another site

旧membership/session/route/grantをfenceし、secret zeroization/self-test後にstockへ戻します。Factory Device Identityは維持します。旧siteのpending transactionを新siteへ暗黙移送しません。

## Controller and Cell Agent

- applicationの現場PCで`ninlild`をSite Controllerとして動かします。
- Parent A/B/C...は同一Ninlil Cell Agent firmwareを使用します。
- Controllerがcell、channel、role、assignment epochを与えます。
- Cell Agent firmwareへ`ParentA`等の固定business variantを作りません。
- 親機はapplication consumerではなく、controllerの手足です。

初期M6は1 Cell Agentです。複数親機はM9でcapacity split、receive diversity、failoverを別目的として実装・測定します。

## Wi-Fi use in applications

給電node/Cell AgentのWi-Fi用途:

- Controller backhaul
- provisioning/service mode
- config/schema/dictionary/font
- OTA and rollback
- logs/core dump/support bundle
- high-frequency telemetry
- BoundedTransfer resume

Battery leak nodeは通常Wi-Fi OFFです。Factory/service modeまたは外部給電時だけ許可します。

Wi-Fi成功をLoRa health成功として記録しません。同じlogical transactionを別bearerで続行する場合も、bearer別Observationとtransaction Receiptを分けます。

## Application policy, not Ninlil default

次はapplication profileで決めます。

- serviceごとのdeadline/SLO
- reserved traffic class
- target group
- display generation/supersede rule
- leak reminder/clear policy
- occupancy aggregation interval
- battery wake schedule
- allowed bearer/path policy
- operator-visible wording

Operator-visible stateは[11-operator-model.md](11-operator-model.md)のstable codeへ写像し、application profileで文言、owner、timeout、runbookを具体化します。特に`OP_RESULT_UNCERTAIN`、`OP_PARTIAL`、`OP_LOCAL_SAFETY`を単なる「失敗」にまとめません。

applicationがrequestごとにarbitrary priorityを上げることはできません。Site policyがservice identityへclass/quotaを割り当てます。

## Migration phases

### Phase A: Preserve

- legacy code/test/buildを凍結
- known benchmarkとgolden fixtureを記録
- production利用とNinlil互換を主張しない

### Phase B: Foundation

- generic command/eventをNinlil simulatorで完成
- application importなし

M1a完了後は、まずsoftware-only `TEST` laneでPC Controller + simulated/optional loopback Endpointとapplication Display/Leak adapterのsingle-target縦切りを実施します。PC + USB Cell Agent + Display + Leak + SX1262のphysical `LAB` laneは、M3のESP-IDF/Cell Agent最小sliceとM5のLAB Tx Gate/radio subsetのgate完了後に開始します。どちらもproduction radioやfield SLOの合格を意味しません。

### Phase C: Hardware ports

- Pico adapter、Leak contact adapter、SX1262 HALをcontractごとに再評価
- private legacy typeをpublic APIへ漏らさない

### Phase D: Reference application adapter

- Display/Leak schemaとServiceDescriptor
- product command/eventとのapplication-level adapter
- Cloud/UI状態語をReceipt/Outcomeへ写像

### Phase E: Cutover

- site/profile単位でNinlil fleetへ移行
- legacy/new混在は明示gatewayなしに直接通信しない
- legacy evidenceはread-only archive
- rollback条件とfield support期限を公開

## M6 acceptance criteria

- reference adapterを除くportable Coreへのapplication固有importが0。
- DisplayはAPPLIED前に反映済み表示されない。
- Leak EventFactはapplication journal commit前にDURABLY_RECORDEDにならない。
- Leak local admission failureがlocal fail-safe、reason、operator表示を持ち、保存済みと誤表示されない。
- EventFact retry cycle枯渇後もsilent discardせず、reconnectで同じidentityを再開する。
- group displayのpartial/unknownがtarget別に表示され、失敗targetだけの再実行は新transactionになる。
- controller/endpoint restart後もcommand/event identityが維持される。
- site move/replacementでold epoch commandを拒否する。
- QR install/remove/reuseがidempotent operation IDを持つ。
- 3台HILの各1,000件gateを満たす。
- legacy wire/DBをNinlil public v1と誤認させる名称がUI/docs/logにない。
