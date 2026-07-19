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
- durable partition storage port（NVS単独ではなく、power-cut契約を満たすbackend）
- identical Cell Agent firmware skeleton
- USB/LAN gateway control transport
- virtual/loopback TxPermit path

Exit gate:

- pinned ESP-IDFでall target build。
- POSIXとESP-IDFで同じportable conformance subsetが通る。
- power-cut HILでstorage contractを満たす。
- Cell AgentにKGuard business ruleが0。

### M3-prep（部分作業; M3 incomplete）

**M3-prep** として次だけを先行実装できます。M3 exit gate の代替ではありません。正本: [18-m3-prep-esp-idf-component.md](18-m3-prep-esp-idf-component.md)。

- portable Core / private library の ESP-IDF component packaging
- concrete ESP-IDF version pin（現在 `v5.5.3`）と host から分離した esp32s3 target compile CI
- component 利用者向け最小 README / smoke app

含まない: USB/LAN driver、power-cut HIL、on-target conformance subset、M3 exit。

### M3 storage port slice（部分作業; M3 incomplete; PR #80 merged）

正本: [21-m3-esp-idf-durable-storage.md](21-m3-esp-idf-durable-storage.md)。

- dual-slot generation marker on wear-levelled partition（**NVS 単独は契約不能のため不採用**）
- `ninlil_storage_ops_t` production 候補 adapter（固定上限・**binder-owned PSRAM workspace**・heap/VLA 禁止）
- host conformance（snapshot / atomicity / ordering / capacity / fault+reopen）
- ESP-IDF component/smoke への compile 接続と map/stack/public-API gates

**状態:** implementation merged（PR #80）。**power-cut HIL 未実行**、ESP FULL production 未証明。M3 exit の代替ではない。

含まない: 実機 power-cut HIL PASS、field-ready 宣言、M3 exit gate 全体、USB/radio/Site Membership・Attachment（Network Join umbrella）/KGuard。

### M3-slice: control byte-stream framing（部分作業; M3 incomplete）

USB CDC / TCP 等の reliable byte stream 上で共通に使う **transport-agnostic bounded control frame codec** だけを先行できます。正本: [19-m3-control-byte-stream-framing.md](19-m3-control-byte-stream-framing.md)。

- private `NCG1` frame encode / one-shot decode / 1-byte incremental parser
- magic/version/type/flags/stream_or_cell_id/sequence/length/header CRC/frame CRC、fail-closed resync
- host golden + mutation tests、ESP-IDF component private source への接続

含まない: USB/CDC driver、TCP socket、logical control messages、custody/Application Receipt、security、M3 complete。

### M3-basic platform adapters（部分作業; M3 incomplete）

**M3-basic** として clock / entropy / execution context の ESP-IDF adapters を先行できます。正本: [20-m3-basic-esp-idf-platform-adapters.md](20-m3-basic-esp-idf-platform-adapters.md)。

- `esp_timer` clock（boot-local epoch/trust/reboot 境界を仕様で固定）
- `esp_fill_random` entropy（invalid args / fail-closed）
- FreeRTOS current task identity の execution context（owner-task confinement に使える identity）
- port-owned factory headers（`ports/esp-idf/include/ninlil_esp_idf/`）。`include/ninlil` public ABI は変更しない
- host pure-logic tests + packaging gate + esp32s3 smoke link

含まない: storage FULL attestation、USB/LAN driver、Wi-Fi、SX1262、Join、KGuard、HIL、M3 exit。

### M3-slice: owner-task / Cell Agent skeleton / loopback TxPermit（部分作業; M3 incomplete）

**M3-slice** として FreeRTOS owner-task adapter、汎用 Cell Agent firmware skeleton、virtual/loopback TxPermit path を先行できます。正本: [22-m3-owner-cell-agent-skeleton.md](22-m3-owner-cell-agent-skeleton.md)。

- dedicated owner task の exclusive confinement と bounded mailbox（overflow = backpressure、silent drop 禁止）
- start / stop / restart、stale generation rejection、generation wrap fail-closed
- 同一 firmware へ Controller から cell/channel/role assignment（KGuard / ParentA/B variant なし）
- NCG1 framing との境界（decode OK ≠ assignment apply）
- TxPermit deny-by-default、`TEST` + explicit loopback のみ許可、将来 M5 provider へ交換可能な `ninlil_tx_gate_ops_t`
- host pure tests + packaging gate + esp32s3 smoke compile/link

含まない: USB/TCP driver、Wi-Fi、SX1262、Site Membership / Attachment（Network Join umbrella）、実 radio、logical control message schema、public Runtime body、security 完了、HIL、M3 exit。

### U0: USB / physical radio boundary freeze（docs only; 本 slice）

USB production と SX1262 production の **前** に依存方向と境界を固定する。正本: [ADR-0003](adr/0003-radio-usb-dependency-direction.md)、[23-usb-radio-boundary.md](23-usb-radio-boundary.md)。

- compile/source dependency と runtime call/data flow を分離（Core / byte-stream contract / NCL1 session / adapters / composition pump）
- runtime physical TX 順序: immutable wire plan → Compliance Permit(exact) → HAL transmit-with-permit → SX1262（sole physical TX edge）
- ownership、private session object + payload ownership、bounded queues（entry+byte; profile default）、RX overflow 時 parser/session fence、POSIX UX（termios/DTR/exclusive/`cu.*`）
- NCL1 最小 envelope と HELLO/PING/PONG/RESET（Controller-only initiator、**NCL1 header session_cookie 全 active 検証 + CSPRNG fail-closed**、NCG1 sequence U4 policy、opaque echo token、CTRL_ERROR loop 閉鎖）
- Physical Compliance Permit に SiteAssignment identity/revision/epoch bind; secure radio wire version は **U0 時点 unallocated**（**R6** で `wire_profile_id=0x11` docs draft 初割当; [30章](30-r6-secure-radio-wire.md)）
- Owner Task Join ACK と Site Membership / Attachment（曖昧 umbrella Network Join）の文書分離
- 独立 slice **U1–U7** / **R1–R10**（R9 は少なくとも R4+R5+R7; **Required HIL** なしに USB series 完成を名乗らない; **compile ≠ HIL**）

含まない / **U0 時点で未確定だったが後続で freeze 済みのもの**: 完全 assignment / Transport Custody の control catalog は **U5/U6 docs freeze** へ移動（下段）。

含まない / **今回未確定（後続 freeze）**: USB/SX1262 production code、security session protocol、**Network Attachment/Join**、**relay**、**multi-parent**、public ABI 昇格、M3/M5 exit。

### U5: CellOperatingAssignment freeze（docs only; 実装未）

正本: [25-u5-cell-operating-assignment.md](25-u5-cell-operating-assignment.md)、[ADR-0005](adr/0005-u5-cell-operating-assignment-control-v2.md)（Accepted）。

- NCL1 envelope v1 維持。v1 closed catalog 非拡張。**negotiated control protocol v2** で assignment catalog を exact freeze
- RuntimeRole / logical link role / mutable CellOperatingAssignment の三層分離
- volatile session-bound assignment（reconnect 失効 + 新 session exact replay; 永続 LKG 非主張）
- LAB_ONLY / EXTERNAL_VERIFIED authority proof 境界（USB HELLO ≠ FIELD RF）
- host NCG1+NCL1 vectors / ESP compile / HIL nonclaims

**状態:** docs freeze。**U5 complete / 実装 / FIELD EXTERNAL suite 完成ではない**（blocker B-U5-AUTH-SUITE 等は 25章）。

### U6: Transport Custody freeze（docs only; 実装未）

正本: [26-u6-transport-custody.md](26-u6-transport-custody.md)、[ADR-0006](adr/0006-u6-transport-custody.md)（Accepted）。

- OFFER/ACCEPT/REJECT/BUSY exact wire; dual FULL commit; release policy
- COMMIT_UNKNOWN 両 truth recovery; Application Receipt 分離
- raw CDC / NCG1 / ACK enqueue ≠ custody success
- single-frame payload ≤926; fragmentation 非主張
- host pure/SQLite crash injection; **ESP custody success は power-cut HIL 後のみ**（21章）

**状態:** docs freeze。**U6 complete / ESP FULL custody success ではない**（blocker B-U6-ESP-FULL）。

### R4: SX1262 control-plane backend（host candidate; RF TX 未）

正本: [28-r4-sx1262-control-plane-backend.md](28-r4-sx1262-control-plane-backend.md)、[ADR-0008](adr/0008-r4-sx1262-control-plane-backend.md)（**docs/25–26 / ADR-0005–0006 は U5/U6 予約、docs/27 / ADR-0007 は R3 予約**）。

- portable D1: hard reset / BUSY / allowlisted SPI / STDBY_RC; board config 注入（Seeed pin を Core に hardcode しない）
- `request_transmit` → TX_DENIED、SetTx SPI 0
- host bus spy + CTest `sx1262_r4` + structural `sx1262_r4_gate`
- ESP-IDF private SPI/GPIO bus adapter candidate（control-plane only）

含まない / **名乗らない**: R4 complete、physical RF TX/RX、R9 sole-edge、Japan/legal、HIL PASS、public ABI。

### R2: Physical Compliance Permit authority（private host candidate）

P1 durable one-shot と R1 watermark の関係を閉じる。正本: [24-r2-physical-compliance-permit-authority.md](24-r2-physical-compliance-permit-authority.md)、[ADR-0004](adr/0004-r2-durable-permit-authority.md)。

- clock sample ABI; **CLOCK_FENCE 解除は fresh epoch 必須**（壊れた same-epoch 禁止）
- FIFO + **advance_expired_heads**; I1–I14; unique storage map; create-on-open
- **ops→user** bind; **publish_initial_meta** exact; **ram_validate** seq+digest+epoch
- **ceiling vs per-permit airtime**; Algorithm R **clockless**; GC exact; close void
- **`pcp_r2_docs_gate`** semantic + §14 vectors + private runtime authority host tests

含まない: R5 production profile、SX1262 RF TX、Japan production 数値、legal certification、RF/HIL、public ABI。

### R3: LoRa airtime calculator（host candidate）

closed SX1262 LoRa domain の決定的 ToA（µs）。正本: [27-r3-airtime-calculator.md](27-r3-airtime-calculator.md)、[ADR-0007](adr/0007-r3-airtime-calculator.md)、`src/radio/airtime_calculator.{h,c}`。

含む:

- SF/BW/CR/header/CRC/preamble/LDRO closed domain + AUTO 閾値一意
- float 無し整数 ceil-to-us; overflow taxonomy
- independent Python oracle + C bridge + `airtime_r3_gate`
- private runtime archive / ESP component 配線（tests-OFF に oracle 非混入）
- R2 per-permit `max_airtime_us` 候補の受渡し契約

含まない: Japan production 数値、duty/LBT/legal、R5 profile、R2 authority body、SX1262 SPI TX、RF/HIL、**R3 complete**、public ABI。

### R5: LAB_ONLY profile loader + full permit bind（host candidate）

正本: [29-r5-lab-only-profile-loader.md](29-r5-lab-only-profile-loader.md)、[ADR-0009](adr/0009-r5-lab-only-profile-loader.md)、`src/radio/profile_loader.{h,c}`。

含む:

- LAB_ONLY HardwareProfile / RegulatoryProfile canonical loader（非 LAB fail-closed）
- §9.3 全 bind 項目の発行時・consume 時 exact 検査（SiteAssignment / controller_term / assignment_digest / permit_bind_generation 含む）
- R3 airtime → R2 per-permit max_airtime + profile ceiling
- R1 permit_ops 互換（sole transmit-with-permit 迂回なし）
- `profile_r5` CTest + `profile_r5_gate` mutation self-test

含まない: FIELD/PRODUCTION、Japan production 数値、legal certification、RF/HIL、**R5 complete**、U5 wire apply、R4/R7/R9、public ABI。

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
- Physical Compliance Permit / airtime ledger（logical TxPermit と分離; [23章](23-usb-radio-boundary.md) §9; **R2 authority 正本** [24章](24-r2-physical-compliance-permit-authority.md)）
- secure compact radio wire の **Normative freeze Accepted**（`wire_profile_id=0x11` NRW1 no minor; one-way contexts / DATA·ACK lanes / E2E security id / CELL_64_V1; **R6 docs freeze** — 正本 [30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md) **Accepted**; independent re-GO 2026-07-19 P0=P1=P2=0; R7 full AEAD / M4·M5 / ESP N6 capacity / RF·USB 実機 HIL / legal / production 未完）
- **Chunk D private N6 host candidate**（`src/radio/n6_*`; portable private durable codec/context; fixed-hash integration GO; M4/M5/ESP fail-closed; **not** R7 full AEAD complete / **not** ESP N6 ready / **not** production radio; ESP `max_namespaces=2 < 3` 等は R7/port blocker）
- **R7 T0 private crypto provider candidate**（[31章](31-r7-crypto-provider-and-aead.md) / [ADR-0011](adr/0011-r7-crypto-provider-boundary.md) Proposed; portable validation + Host OpenSSL exact 3.x + ESP-IDF mbedTLS + 37-vector bridge; local acceptance P0=P1=P2=0）。**Remote CI確認まではT0 Acceptedにしない。T0はR7 full wire/state/FRAG/LINK/CELL/HA、実機KAT、RF/USB HIL、legal、production radioを完成させない。**
- SX1262 HAL/backend（R1–R10; permit なし TX path 0）
- `LAB_ONLY` radio profile

Exit gate:

- 05章security/compliance acceptance。
- permit bypass 0。
- nonce/replay/power-loss fault test。
- 対象lab hardwareでfrequency/time-on-air/LBT measurement（R10; compile 成功の代替不可）。
- 国内実運用可能とはまだ表示しない。

実装は [23章 §10.2](23-usb-radio-boundary.md) の **R1–R10** に分割する。R2 は [24章](24-r2-physical-compliance-permit-authority.md) に従う。**R6 Normative freeze Accepted（docs/30）が `wire_profile_id=0x11` を post-attachment data として割当済み**（major/minor なし; independent re-GO 2026-07-19 P0=P1=P2=0）。R7 以前に別経路で production radio wire bytes を再固定してはならない。**M4 Attachment handshake / join bootstrap 実装は未完了**（別 profile; 0x11 は pre-context-install で app TX/RX=0）であり、R6 docs freeze は security-session **input contract** のみ固定する（R7 full AEAD / M5 complete / 実機 HIL を偽装しない）。

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
