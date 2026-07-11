# 09. Roadmap

状態: Normative milestone plan<br>
原則: feature数ではなく、上位機能が依存する不変条件の順に進める

## M0: Specification Baseline

状態: Complete (2026-07-10, D-042)

内容:

- Ninlil Runtimeへの改名
- `ninlil/`を次期仕様正本へ変更
- Legacy LinkOS Lab v1の凍結
- 00〜14の仕様
- Fableの思想・使いやすさ・OSS観点レビュー
- decision log更新

Exit gate:

- Foundation実装者がAPI、state、ownership、storage、resource、testを独自判断しなくてよい。
- Fableの重大指摘を反映または理由付きで不採用記録した。
- security/complianceの技術的正当性をFableへ委ねていない。
- Foundation blockerと後続milestone blockerを分離した。

## M1a: Foundation Single-target Transaction Kernel

正本: [08-foundation-release.md](08-foundation-release.md)

内容:

- frozen public C ABIとreason code registry
- DesiredStateCommand / EventFact
- single concrete target、admission assurance、idempotency、finite local reservation
- restart-safe Controller / Endpoint storage
- simulated bearer
- EventFact no-deadline / parked retry / audited discard
- generic examples

Exit gate:

- Foundation acceptanceを全て満たす。
- controller/endpoint crash matrixでfalse success、ownership loss、contract外duplicate effectが0。
- KGuard importが0。

## M1b: Foundation Composition

内容:

- multi-target rosterと`ALL_TARGETS`
- target別Outcomeと決定的aggregate
- group partial-result query
- POSIX loopback bearer example
- M1a ABIを破壊しない追加API

Exit gate:

- mixed target outcomeの全組合せが13章のprecedenceと一致する。
- 失敗targetだけの再実行が新transactionとして追跡される。
- 2 process loopback exampleがloss/restart込みでgeneric command/eventを完了する。

## Experimental KGuard validation lanes

Hardwareの成熟度をM1aに偽装しないため、2段階に分けます。

### Lane A: software-only TEST validation

M1a exit gate完了後、M1bおよびM2〜M5と並走して開始できます。

- PC Controller + simulated bearerまたはoptional POSIX loopback Endpointを使う。
- KGuard Display/Leak schema adapterをNinlil public APIだけで駆動し、single-target `APPLIED`、Event `DURABLY_RECORDED`、再起動、local admission failureを検証する。
- Environmentは`TEST`で、USB実機、SX1262、radio TX、実credentialを使わない。

### Lane B: physical LAB validation

M3のESP-IDF/Cell Agent最小sliceと、M5のLAB environment、credential、Tx Gate、SX1262 bearerの必須subsetがそれぞれ自身のgateを満たした後だけ開始します。

- PC + USB Cell Agent + Display + Leak nodeを使い、Legacy SX1262/Pico/contact adapterは`experimental`に隔離する。
- `LAB`として明示し、production radio、法規適合、security完了、RF SLO合格の代わりにしない。
- spikeで得た都合のためにM1a public contractを暗黙変更しない。変更はADR/RFCとgeneric conformance testへ戻す。

## M2: Remaining application contracts

内容:

- LatestState
- MeasurementBatch
- ConfigRevision公開family（内部はTransfer + Command合成可）
- BoundedTransfer manifestのlogical API
- target resolver extension
- counter-offer生成・保存・acceptance race
- subscription/event API

Exit gate:

- familyごとのbackpressure、retention、supersede/aggregationがmodel testで証明される。
- BoundedTransferはsimulatorでpartial apply 0。
- Foundation APIをbreaking changeせず追加できるか、必要なら0.x migrationを明示する。

## M3: ESP-IDF Port and Cell Agent skeleton

内容:

- ESP-IDF component packaging
- FreeRTOS owner-task adapter
- NVS/partition storage port
- identical Cell Agent firmware skeleton
- USB/LAN gateway control transport
- virtual/loopback TxPermit path

Exit gate:

- pinned ESP-IDFでall target build。
- POSIXとESP-IDFで同じportable conformance subsetが通る。
- power-cut HILでstorage contractを満たす。
- Cell AgentにKGuard business ruleが0。

## M4: Identity Lifecycle

内容:

- Device Identity
- Site Membership
- Attachment state machine
- Route Lease / Traffic Grant lifecycle（1-hop）
- QR management API mapping
- install / commission / drain / remove / reuse
- single active Controller fencing

Exit gate:

- site A -> stock -> site B移設
- known node offline reattach
- replacement without identity copy
- old membership/session/route/grant frame rejection
- forced move split-risk表示
- Join storm simulator

## M5: Session Security and Compliance

内容:

- Attachment handshake RFC実装
- session key / nonce / replay
- Hardware/Regulatory Profile loader
- TxPermit / airtime ledger
- SX1262 HAL/backend
- `LAB_ONLY` radio profile

Exit gate:

- 05章security/compliance acceptance。
- permit bypass 0。
- nonce/replay/power-loss fault test。
- 対象lab hardwareでfrequency/time-on-air/LBT measurement。
- 国内実運用可能とはまだ表示しない。

## M6: KGuard Reference Vertical

内容:

- KGuard application adapter
- Display DesiredStateCommand/APPLIED
- Leak EventFact/DURABLY_RECORDED
- USB-connected Controller + Cell Agent + 2 Endpoints
- legacy/new evidence比較tool

Exit gate:

- Display command 1,000件、EventFact 1,000件。
- Controller/Endpoint再起動込み。
- false success、silent event loss、contract外duplicate effect 0。
- KGuard schema/policyがNinlil Coreに混入しない。

## M7: Scheduler, Sleep and Wi-Fi/USB bearer

内容:

- traffic class/quota/fairness
- sleepy receive window admission
- Wi-Fi/USB offload
- origin/cell custody policy
- management bulk separation
- 50-node deterministic simulator/load generator

Exit gate:

- `NINLIL-FIELD-50-A` simulator profile。
- 重要trafficがbulk/noisy neighborでstarveしない。
- battery scan/wake budgetをreport。
- Wi-Fi断でもLoRa/local safety pathが継続。
- simulator結果をRF実証と表現しない。

## M8: Relay Tree / Forest

内容:

- controller-managed route tree/forest
- primary/backup parent
- hop-by-hop mutable metadata protection
- relay load/airtime/power scoring
- drain/removal assessment
- emergency contention path

Exit gate:

- 2〜3 hop loss/duplicate/reorder。
- loop/stale lease rejection。
- planned drain、sudden relay failure、sleepy descendant。
- alternate routeなしをsuccess表示しない。
- 100-node topology simulation/soak。

## M9: Multi-cell / Multi-parent

内容:

- identical Cell Agentへcell/channel/role assignment
- uplink receive diversity/dedup
- downlink single-owner fencing
- capacity cell split
- parent failure/migration
- multi-radio capability

Exit gate:

- parent loss、backhaul loss、duplicate uplink、split-brain downlink。
- transaction identityを維持したfailover。
- capacity目的とredundancy目的を別profileで測定。
- N+1 capacityなしに同一SLOを保証しない。

## M10: Field Pilot

内容:

- deployment-approved Japan profile候補
- production provisioning
- target hardware/antenna evidence
- field support bundle
- operator runbook、rollback、field support期限
- compatibility/deprecation方針とpilot中のupgrade window
- KGuard pilot traffic profile
- RF/load/battery/soak測定

Exit gate:

- 法規・認証担当による外部確認。
- independent security review。
- 24h以上のprofile soakとfield pilot acceptance。
- submitted/admitted/rejected/outcome/late evidenceを全報告。
- claimsが実測範囲を超えない。

## M11: Public Alpha to 1.0

内容:

- NOTICE要否、third-party dependency license、source distribution表示、SBOMを含むlicense/compliance最終監査
- English normative docs
- CONTRIBUTING / CODE_OF_CONDUCT / SECURITY / governance
- package/release signing/SBOM
- API/reference/porting/tutorial/how-to
- 1.0 compatibility/deprecation/LTS policyの確定（pilot前方針を正式supportへ昇格）
- third-party implementation conformance

Exit gate:

- 外部developerがKGuardなしでbuild、example、test、portを実行できる。
- release checklist、compatibility matrix、migration policyが運用されている。
- 1.0 public API/wire/profileのsupport期間を宣言できる。
- NOTICEと依存licenseの必要表示が監査され、SBOMおよび配布artifactと一致する。

## Dependency rule

Milestoneを飛ばして後続機能をproduction対応と呼びません。Prototypeは可能ですが、前段exit gateを満たさない実装は`experimental`に隔離します。

特に、M1aのrestart-safe transaction kernelを完成させる前に、relay、TDMA、multi-parentへ本実装を広げません。経路が増えるほど、identityとcrash recoveryの欠陥が増幅するためです。
