# 37. Ninlil Runtime 1.0 integration program

状態: **Proposed — V2 / 1.0 completion program; implementation authorityではない**  
Decision: [ADR-0038](adr/0038-runtime-1.0-integration-program.md)

## 1. 目的と既存V1との関係

本章はprivate NJM1 LABを製品名へ変える文書ではない。公開`Runtime`、`Fabric v1`、
`Composition v1`と既存のIdentity / Attachment、secure radio、relay、multi-parent、
multi-frame、Wi-Fi候補を、一つのNinlil Runtime 1.0へ接続する依存順を示す。

[ADR-0034](adr/0034-v1-functional-lab-scope.md)が固定したV1は、single-hopの
**LAB_ONLY functional SDK**であり、状態上限は`HIL_VERIFIED`のまま変更しない。
Production Attachment、relay、multi-parent、MFDT、Wi-Fi実経路、M1b/M2、
`RELEASE_SUPPORTED`はV2 / Runtime 1.0の対象である。

[34章](34-v2-runtime-fabric-completion.md)は現時点でProposedの完成契約候補であり、
単独では実装根拠にならない。1.0完成判定に使うには、同章と対象機能の関連ADRが
S1〜S6を満たして`SPEC_ACCEPTED`にならなければならない。

## 2. 現在の正確な状態

| 領域 | 現在 | 1.0に必要なこと |
| --- | --- | --- |
| Portable Runtime | 複数Service、DesiredState、EventFact、期限、再送、dedupe、Receipt、query/listはHost候補 | M1a/M1b exit gateとimmutable release evidence |
| LatestState / Measurement / Transfer / Config | public enumは予約のみで、登録は`UNSUPPORTED` | M2仕様、Accepted unfreeze、ABI/storage/backpressure/Host/ESP受入 |
| Fabric / Composition | 公開experimental packageとbase ownerは実装済み | Accepted internal enginesを同じbounded ownerへ接続 |
| Production Attachment | docs/35とADR-0023はProposed、PA-S1〜S6はOPEN | real EDHOC owner、durable install、restart/revoke、carrier HIL |
| SX1262 data path | R5 permit→R1→R9の物理候補とprivate packet linkがある | Accepted mapping、Attachment binding、Fabric provider、実機E2E |
| Relay / multi-parent | Accepted designとprivate software候補 | M8/M9のComposition接続、simulation、HIL、failover受入 |
| Multi-frame / Wi-Fi | private software候補 | M7と関連ADR、MFDT contract、実AP/large-data/restart HIL |
| automatic Join / topology UI | NJM1 private LABで3台HIL済み | production trust、正式management schema、provenance付き観測 |

NJM1のwire、site state、route table、unauthenticated Joinは正式Runtimeへ昇格しない。
再利用できるのは同一ESP image、bounded owner loop、SX1262実測timing、診断方法、
実機試験手順に限る。

## 3. 1.0の利用者向け完成像

Runtime 1.0は少なくとも次を一つのSDKとして提供する。

1. 同じESP32-S3 imageで、一つのnodeが複数Serviceを同時に持てる。
2. Applicationは特定nodeの特定Serviceへ命令し、event、query、state、measurement、
   bounded transferを公開contractどおり扱える。
3. ApplicationDataはopaque bytesであり、Application schemaをCoreへ入れない。
   packet MTUを超える内容はApplicationからfragmentを見せずに分割・再構成する。
4. factory identity、Site Membership、Attachment、Route Lease、Traffic Grantを分離し、
   設置、撤去、在庫化、別siteへの移設、revoke、restartを扱う。
5. nodeは認証済みparentを選び、最大3 hopをrelayし、親消失時にfalse successなしで
   代替routeへ移る。multi-parentではsingle downlink ownerをfenceする。
6. macOS/Linux Controllerはprovenanceとage付きtopology、link品質、route、
   transaction outcomeを観測できる。remote Service directoryは、既存roadmapへ追加する
   Accepted management contractができるまで完成扱いにしない。
7. Wi-Fi、USB、SX1262は同じFabric policyで選択され、transport固有情報をApplication
   contractへ混入させない。
8. permit経路を迂回するRF送信は0である。法規適合と特定hardwareの国内運用可否は、
   Runtime完成とは別の外部証拠で閉じる。

特定製品の業務語彙はCore、wire、storage、public APIへ入れない。

## 4. Ownerとwork budgetを増やさない

```text
Identity / Attachment provider
        | validated binding + invalidation
        v
Composition v1  (single public owner / bounded step)
        |
        +-- Runtime work: Foundation + Runtime-owned MFDT
        +-- reliability_work: RRMP route/parent + radio FRAG only
        +-- Fabric work: USB / Wi-Fi / SX1262 packet-link providers
```

- Applicationは`Runtime`だけを使い、raw route、parent、fragment、radio frameを操作しない。
- portは`Fabric`へ登録し、別transport managerや二つ目のRuntime pumpを作らない。
- MFDTはAccepted ADR-0032どおり`budget.runtime`を消費する。Compositionから二重stepしない。
- `reliability_work`はroute/parentとradio fragmentationだけに配分する。
- Production Attachment producer/carrierはcanonical management pathで進む。同じplatform
  owner task内の別bounded workとして仕様化し、Compositionはvalidated provider結果だけを
  消費する。予算と順序がAcceptedになるまで暗黙のbackground loopを追加しない。
- short payloadはMFDTを通さず、必要なpayloadだけを既存MFDTへ渡す。

## 5. Identity / Attachment実装開始gate

`ninlil_identity_attachment_precondition_v1`を唯一の有効化handoffとし、別の簡略
Activation DTO、raw secret、QR由来boolean、LAB bindingを正式側へ追加しない。

consumer実装を始める前に、次を同じspec changeで閉じる。

1. [ADR-0028](adr/0028-composable-public-runtime-modules.md)のidentity-precondition subset、
   または同じexact contractを抽出した専用ADRを`SPEC_ACCEPTED`にする。
2. `compatibility-matrix.json`の`identity-attachment-session-install`を、実際に揃った
   S1〜S6 evidenceに対応する状態とceilingへ更新する。
3. `resolve -> validate -> subscribe -> publish`、admission/send前再validation、
   invalidation drain、provider-owned non-exporting key handle、restart floor、release順を固定する。
4. Domain Storeをsole writerから外すなら、実装で迂回せずADR-0028、manifest、matrixを
   spec-firstで改訂する。外さない限り308-byte restart floorとsingle-writer契約を維持する。

このgate前のconsumer code、Host fixture、LAB bindingはProduction Attachmentの証拠にならない。

## 6. 既存trancheへの依存順

以下は新しいstatus体系ではない。現行正本はPA-Sとroadmap Mであり、34章C1〜C10は
`SPEC_ACCEPTED`後だけcompletion authorityへ加わる。本表は依存関係だけを示す。

| 順序 | 既存authority / 必要なclosure |
| --- | --- |
| 1 | §5 identity-precondition contractを`SPEC_ACCEPTED`にし、Composition consumer seamをHost/installed-consumerで検証する。consumerだけではmaturityを上げない |
| 2 | PA-S1〜S4でdirect Production Attachment、15-key FULL install、dual confirmation、zeroizationを閉じる。Attached後だけ公開Composition経由でApplicationData/Receiptを通す |
| 3 | M5/M7とAccepted radio mappingに従い、scheduler、Wi-Fi/USB、NFL1↔NRW1、R7/R9/R5 sole edge、通常のFabric provider、M7 exit gateを閉じる |
| 4 | PA-S5/S6でrestart、rotation、revoke、site move、join storm、USB/Wi-Fi/SX1262 direct HILを閉じる。この段階は全nodeがControllerへdirect attach可能という限定profile |
| 5 | relayが必要とするAccepted NRW1 LINK/FRAGとU6 carrier contractを閉じる |
| 6 | Controller範囲外nodeのcold Join用pre-Attachment opaque forwardingを新たにspec-firstで定義する。NAR1やNJM1を再解釈しない |
| 7 | M8でRRMP single-parent、最大3 hop、route lease、drain、突然死、100-node topology simulation/soak、3台以上のRF HILを閉じる |
| 8 | M9でmulti-parent、uplink diversity、single downlink owner fencing、2 parent + 1 Endpoint split-brain HILを閉じる |
| 9 | M10 field pilotとM11 Public Alpha to 1.0、およびSPEC_ACCEPTEDになった34章C1〜C10を閉じる |

[roadmap M1b](09-roadmap.md#M1b-Foundation-Composition)、
[M2](09-roadmap.md#M2-Remaining-application-contracts)は、上表のnetwork laneと並行して
全項目・exit gateをそのまま閉じる。Runtime-owned MFDTも独立parallel laneで進め、
いずれもM11の前に合流させる。
[ADR-0024](adr/0024-m1a-public-family-matrix-freeze.md)のreserved familyは、専用Accepted
ADRなしに有効化しない。

formal RRMPの有効化とphysical acceptanceはactive Attachmentより先に進めない。既存private
RRMPの単体実装・Host試験は保持できるが、Production route claimには使わない。

## 7. 最低受入シナリオ

1. 同一nodeの3 Serviceでcommand受信、event送信、periodic/query responseを同時処理する。
2. Controller→relay→endpointのcommandと、endpoint→Controllerのevent/Receiptを通す。
3. relay drain、突然停止、代替parent、routeなしの明示failureを検証する。
4. site A→revoke/stock→site Bで旧epoch/session/route/grantをすべて拒否する。
5. ApplicationDataのminimum、V1最大、packet MTU境界、multi-frame最大をopaque bytesで検証する。
6. Wi-Fi断で許可されたLoRa pathへ切り替えてもtransaction identityを維持する。
7. Controllerから8 node topologyを表示し、観測不能値を0やhealthyへ偽装しない。
8. M7の50-node scheduler profile、M8の100-node topology soak、M9のsplit-brain HILを縮小しない。
9. 20 Application messages / 10 secondsのprofile試験はsubmitted、admitted、rejected、
   required evidence、latency、retry、airtimeを別々に報告する。合格SLOをfield profileで
   exactに固定するまで未決定値を成功扱いしない。

## 8. 非主張

本章の追加だけでは、V1 LAB、Production Attachment、cold multi-hop Join、RRMP physical
HIL、Wi-Fi AP HIL、M1b/M2、20件/10秒SLO、Japan legal、Runtime 1.0 releaseの状態は
一つも昇格しない。各機能は既存machine-readable authorityと実行証拠に従って進める。
