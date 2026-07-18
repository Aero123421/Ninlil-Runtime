# 05. Security and Compliance

状態: Normative architecture baseline（production profile値は未確定）<br>
Foundation実装: interfaceとfail-closed stub<br>
Production radio実装: 後続RFCと外部確認が必要

## 目的と責任範囲

Security EngineとCompliance Gateを分けます。

- Security Engineはidentity、session、confidentiality、integrity、replay、receipt bindingを扱う。
- Compliance Gateは、指定hardware/profileで今その送信を実行してよいかをhard gateする。
- Schedulerは送信時刻を最適化できるが、Compliance Gateを上書きできない。

Ninlilは法的認証を自動取得・証明する製品ではありません。認証済みmodule/SKU、antenna、出力、設置、法令解釈を含む外部証跡を、versioned profileとして強制するRuntimeです。

2026-07-10時点でARIBの公開ページが示すSTD-T108最新版は1.5（2023-03-03）です。TELECは920MHzデータ伝送用機器の詳細について試験方法と関係法令の確認を求めています。具体的な周波数、LBT、送信時間、休止、出力値は、本draftへ推測転記せず、対象SKUの確認後にRegulatory Profile dataとして追加します。

参考:

- [ARIB STD-T108](https://www.arib.or.jp/kikaku/kikaku_tushin/std-t108.html)
- [TELEC T245 920MHz帯データ伝送用特定小電力機器](https://www.telec.or.jp/services/tech/criterion/t245_01.html)

## Environment profile

Artifactとruntime configurationは次を明示します。

- `TEST`: virtual bearerだけ。production credentialとradio TXなし。
- `LAB`: 公開test credentialまたはlab credentialを使用可能。隔離環境だけ。
- `FIELD_PILOT`: 対象hardwareと限定siteで承認されたprofileだけ。
- `PRODUCTION`: deployment-approved credential/profileだけ。

`PRODUCTION` artifactに公開test key、default key、認証迂回、lab radio profileを含めてはいけません。Environment不明時は`TEST`へfallbackせず、起動を拒否します。

## Security requirements

### Milestone applicability

| Requirement set | First mandatory milestone | Foundation M1a |
| --- | --- | --- |
| `NIN-SEC-001`〜`NIN-SEC-015` production identity/session requirements | M4〜M5 | cryptographic/session provider ABIなし。TEST identity/origin authorizationとenvelope binding validationだけ |
| `NIN-CMP-001`〜`NIN-CMP-013` physical radio requirements（012/013 は logical permit 流用禁止・wire memcpy 禁止; **U0 当時** radio wire unallocated → **R6** で `wire_profile_id=0x11` draft 割当） | M5（概念は U0 boundary freeze で先行定義; wire 正本は [30章](30-r6-secure-radio-wire.md)） | virtual TxPermit pathだけ。physical TXは存在しない |
| secretをlog/support bundleへ出さない基本境界 | M1a | TEST dataを含め全実装必須 |
| unknown environmentをproductionへfallbackしない | M1a | 必須 |

後続milestoneのMUSTをM1aの未達として扱いません。逆に、M1aのstub合格をproduction security/compliance合格と表示してはいけません。Milestone別のgate正本は14章です。

### Identityとkey

- `NIN-SEC-001`: 各deviceは固有root credentialを持たなければならない。
- `NIN-SEC-002`: leafへsite-wide master secretを配布してはならない。
- `NIN-SEC-003`: QR、log、support bundle、receipt evidenceにsecretを出してはならない。
- `NIN-SEC-004`: root credentialをdata frame keyとして直接使用してはならない。Attachmentごとにsession keyとkey epochを確立する。
- `NIN-SEC-005`: key rotation、revocation、quarantine、site move時のold-session fenceを実装しなければならない。

初期suite候補は`AES-128-GCM + HKDF-SHA-256 + 128-bit tag`です。**R6** は secure compact radio wire について本 suite を **`wire_profile_id=0x11`（NRW1; major/minor domain なし）で pin**し、outer/E2E layout・**一方向 context**・hop DATA/ACK 別 lane・**E2E `e2e_security_id`/`e2e_security_epoch`（Attachment 非 bind）**・context lifecycle / durable counter 回復・CELL_64_V1 を [30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md) で固定する（**docs-only Accepted 仮; R7 実装・M4/M5 handshake 実装・HIL ではない**）。M1aはcryptographic provider/session ABIを公開または実装しません。Legacy golden fixtureはlegacy regression用に保持できますが、M1a Core interfaceやNinlil Wire適合の証明に使いません。

### Nonceとreplay

- `NIN-SEC-006`: 同一key epochでnonceを再利用してはならない。
- `NIN-SEC-007`: counter範囲を送信前にdurable storageへ先行予約する。reservation失敗、wrap、破損、epoch不明時はprotected TXを停止する。
- `NIN-SEC-008`: replay windowはduplicate、window外を拒否する。**Hop layer** は `attachment_id`/`attachment_epoch` と `membership_epoch` を binding に含む（[30章](30-r6-secure-radio-wire.md) hop binding）。**E2E layer** は `membership_epoch` と `e2e_security_id`/`e2e_security_epoch` を binding に含む（Attachment id/epoch は E2E binding に含めない）。**Attachment-only change** では E2E context を fence しない（hop は fence/rekey 対象になり得る）。
- `NIN-SEC-009`: 未認証frameを受けてsession、reassembly、queue、logを無制限に割り当ててはならない。

### Application evidence

- `NIN-SEC-010`: Receiptはtransaction ID、concrete target、issuer、stage、schema/content digestまたはgeneration、site/membership epochへbindingする。
- `NIN-SEC-011`: relayとCell Agentは、明示的なapplication gatewayでない限りapplication payloadを復号・変換してはならない。
- `NIN-SEC-012`: E2E application envelopeとmutable hop/route metadataを分け、mutable metadataはhop protectionを持つ。

### Fail closed

- `NIN-SEC-013`: security state、key epoch、storage atomicity、profile bindingを確認できない場合はnetwork application trafficを停止する。
- `NIN-SEC-014`: network停止中もendpoint applicationのlocal fail-safeとphysical interlockを停止してはならない。
- `NIN-SEC-015`: auth failure、replay、revocation、epoch mismatchをbounded structured counterに残す。平文payloadとsecretは記録しない。

## Compliance data model

### HardwareProfile

- hardware profile ID / revision
- device model、radio SKU、hardware revision
- antenna model / gain条件 / connection条件
- certified firmware constraints
- available bearer/radio count
- immutable hardware identity binding

### RegulatoryProfile

- profile schema version / profile ID / revision
- region / radio service category
- applicable HardwareProfile範囲
- external certification/evidence references
- allowed channels / bandwidth / modulation / coding範囲
- power / antenna条件
- carrier sense / LBT rule
- single transmission limit / mandatory off-time
- rolling airtime / duty rule
- airtime formula version
- time authority requirement
- effective / expiry time
- approval state
- signer / approval evidence

Approval state:

- `LAB_ONLY`
- `CANDIDATE`
- `DEPLOYMENT_APPROVED`
- `REVOKED`

Production Runtimeは`DEPLOYMENT_APPROVED`だけを使用できます。

## TxPermit

用語を分ける（[15章](15-glossary.md)、[23章](23-usb-radio-boundary.md)）:

| 用語 | 認可対象 | 備考 |
| --- | --- | --- |
| **Logical / virtual / loopback TxPermit** | simulated bearer および TEST loopback のみ | Foundation M1a / M3 loopback。**physical RF を認可しない** |
| **Physical Compliance Permit** | すべての physical radio TX | 本章および M5 の hard gate。**唯一の physical TX 認可エッジ** |

すべてのphysical radio TXはCompliance Gateが発行するone-shot **Physical Compliance Permit**（歴史的に TxPermit とも呼ぶ）を必要とします。

対象にはapplication dataだけでなく、beacon、Network Join / Attachment control、ACK、receipt、retry、relay、diagnostics、emergency trafficを含みます。

**R2 authority 実装正本:** [24章 §14](24-r2-physical-compliance-permit-authority.md) / [ADR-0004](adr/0004-r2-durable-permit-authority.md) / private `src/radio/pcp_authority.{h,c}` / `pcp_r2_docs_gate` semantic（FIFO·advance·fresh-epoch·ops→user·publish·airtime ceiling; **private host candidate; legal / production profile / RF / HIL completeではない**）。

**R3 airtime 算出正本:** [27章](27-r3-airtime-calculator.md) / [ADR-0007](adr/0007-r3-airtime-calculator.md) / `src/radio/airtime_calculator.{h,c}` / `airtime_r3_*`（closed SX1262 LoRa domain・整数 ceil-to-us; **R3 host candidate; Japan production 数値 / duty·LBT / HIL / R3 complete ではない**）。出力 `airtime_us` は R2 per-permit `max_airtime_us` 候補（ceiling 比較は R2）。

**R5 LAB_ONLY profile / full bind 正本:** [29章](29-r5-lab-only-profile-loader.md) / [ADR-0009](adr/0009-r5-lab-only-profile-loader.md) / `src/radio/profile_loader.{h,c}` / `profile_r5_*`（LAB_ONLY fail-closed; §9.3 全項目 issue/consume; **R5 host candidate; FIELD / Japan / legal / HIL / R5 complete ではない**）。

**R6 secure compact radio wire 正本:** [30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md) / `radio_wire_r6_docs_gate`（`wire_profile_id=0x11` post-attachment data; one-way contexts; DATA/ACK lanes; E2E security id≠Attachment; durable lifecycle; CELL_64_V1; **docs-only Accepted 仮; R7 実装 / handshake 実装 / HIL / R6 complete ではない**）。

Physical Compliance Permit binding（**MUST** bind; [23章 §9](23-usb-radio-boundary.md)）。発行・consume の両方で検査する。

- hardware profile ID / revision
- regulatory profile ID / revision
- **SiteAssignment identity / revision / epoch**（`NIN-CMP-001` 必須）
- **controller_term**（U5 CellOperatingAssignment; [25章](25-u5-cell-operating-assignment.md) / [23章 §9.3](23-usb-radio-boundary.md)）
- **assignment_digest**（U5 canonical assignment digest; 同上）
- **permit_bind_generation**（U5 ARW; [25章 §8.5](25-u5-cell-operating-assignment.md) — assignment apply ごとに単調増加; 旧 generation の permit は consume 拒否）
- **physical transmitter identity**（physical radio path; Foundation `ninlil_bearer_*` ではない）
- channel / PHY（live radio settings; R1 `live_binding` / 24章 Live bind set L）
- frame digest and byte length（immutable TX plan; permit 発行後の変更禁止）
- conservatively calculated maximum airtime（**R3** が ToA 候補を算出し owner が R2/R1 へ渡す; profile 上限は R5）
- not-before / expiry
- permit sequence

**Physical TX 順序（Normative; [23章](23-usb-radio-boundary.md) / [ADR-0003](adr/0003-radio-usb-dependency-direction.md)）:**

1. secure wire/MAC が immutable TX plan / exact bytes を確定する。
2. Compliance Gate が SiteAssignment（identity/revision/epoch/**term**/**assignment_digest**）× profiles × live settings × ledger を検査・予約し、**exact plan** へ Physical Compliance Permit を発行する。
3. `ninlil_radio_hal` の **sole** transmit-with-permit 入口が再検証し single-use consume する。
4. SX1262 backend が送信する。

SiteAssignment（identity/revision/epoch/term/digest）/ profile / live radio settings / frame digest・length・PHY が発行時スナップショットと異なれば **consume 拒否**（新 plan + 新 permit のみ）。
CellOperatingAssignment mutation/replacement 時は outstanding permit を **atomic fence** する（[25章](25-u5-cell-operating-assignment.md)）。R2 Normative 正本は [24章](24-r2-physical-compliance-permit-authority.md) / ADR-0004（main 統合済み）; U5 fence/bind と **docs 整合済み**。R2 **runtime complete は主張しない**。

規則:

- `NIN-CMP-001`: `HardwareProfile × RegulatoryProfile × SiteAssignment × live radio settings`が一致しなければpermitを発行してはならない。SiteAssignment は identity / revision / epoch に加え、U5 以降 **controller_term と assignment_digest** を含む。
- `NIN-CMP-002`: Physical Compliance Permitなしでdriver TXへ到達するcode pathを作ってはならない。sole edge は transmit-with-permit のみ。
- `NIN-CMP-003`: permitは一度だけ消費し、expiry後に使用してはならない。発行後の bytes/PHY 差替えは禁止。
- `NIN-CMP-004`: application、scheduler、operator、USB control pathのpriorityはCompliance denialを上書きできない。
- `NIN-CMP-005`: permit denialをqueued、sent、received、appliedとして表示してはならない。
- `NIN-CMP-012`: Foundation logical / virtual / loopback TxPermit を physical RF 送信許可として流用してはならない。
- `NIN-CMP-013`: logical bearer message や public transaction struct を `memcpy` して radio wire にしてはならない。**U0 時点**では secure radio wire version は unallocated だった。**R6** で `wire_profile_id=0x11` として docs-only draft 固定（[30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md); major/minor なし）。**R7 encode/decode·AEAD 実装 / HIL / production radio complete ではない**。

## Airtime ledger

Physical transmitterを所有するRuntimeがledgerの正本です。Controllerのairtime見積りはadmission用であり、最終送信許可ではありません。

- `NIN-CMP-006`: airtimeをTX前に保守的に予約する。
- `NIN-CMP-007`: TX成否が不明な場合は予約量を消費済みとして扱う。
- `NIN-CMP-008`: retry、ACK、receipt、control、relay frameをすべて計上する。
- `NIN-CMP-009`: rebootでrolling budgetを過小計上してはならない。
- `NIN-CMP-010`: ledger破損、clock rollback、checkpoint failure時はTXを停止する。
- `NIN-CMP-011`: persistent checkpointはflash wearをboundedにしつつ、未使用予約を消費済みとみなす保守的tranche方式を使用できる。

## Profile変更

- profile変更はversioned revisionとしてstage、validate、activateする。
- active TX reservationがあるprofileをin-place変更しない。
- rollbackは旧profileが現在も承認済みである場合だけ許可する。
- 誰が何の証跡で承認したかをaudit recordへ残す。
- unknown rule/profile schemaへ遭遇した場合、古いdefaultへfallbackせずTXを停止する。

## Diagnostics

Operatorへ最低限、次を区別して示します。

- hardware/profile mismatch
- profile未承認または期限切れ
- LBT/carrier busy
- legal/ledger budget待ちと次回候補時刻
- ledger recovery required
- radio hardware failure
- path/capacity rejection

「profileが読み込めた」を「法的に使用可能」と表現してはいけません。

## Foundation implementation

Foundation Releaseでは次だけを実装します。

- `TEST` environmentのsynthetic identityとorigin authorization provider
- typed envelopeのtransaction/attempt/source/target/service/digest/epoch binding validation
- permitを必須化するvirtual Tx Gate / simulated bearer
- unknownまたはM1a非対応environmentをfail-closedに拒否する境界
- secretをlog/support bundleへ出さない共通境界

Typed envelopeはM1aでcryptographically authenticatedとは表現しません。Cryptographic provider、session、replay window、nonce reservationはM4〜M5でexact ABI/wireを定義します。Legacy AES-GCM vectorはlegacy regression fixtureであり、M1a conformance matrixに含めません。

実radio、production provisioning、session handshake、Japan deployment profileはFoundationに含めません。

## Acceptance tests

M1a boundary:

- TEST origin authorizationのallow/deny/temporary/permanent/invalid decision mapping
- transaction/attempt/source/target/service/digest/epoch bindingの各1項目不一致をreducer前に拒否
- virtual permitの未取得、mismatch、expiry、one-shot再使用でBearer send 0
- unknownまたはM1a非対応environmentの起動拒否
- TEST dataを含むlog/support bundleにsecret扱いfieldが出ない

M4〜M5 security（M1a gateではない）:

- cross-language cryptographic golden vector
- header/ciphertext/tag/receipt bindingの各1-bit改変拒否
- duplicate、reorder、window外、別epoch replay
- reboot、torn write、counter reservation失敗、counter wrapでnonce再利用ゼロ
- production artifactへtest keyが含まれた場合のbuild failure
- unauthenticated inputへのresource allocation上限

M5 physical compliance（M1a gateではない）:

- spy radio portでpermitなしTXがゼロ
- profile、hardware、antenna、channel、power、revisionの各1項目不一致を拒否
- airtime calculatorを独立reference vectorと比較（**R3 host:** `airtime_r3_oracle` + `airtime_r3_bridge`; Japan/HIL 非主張）
- ledger境界、concurrent request、retry/ACK加算、reboot、clock rollback、corruption
- 設定周波数、出力、time-on-air、LBT timingを対象SKUで測定

## Release gates

| Maturity | Gate |
| --- | --- |
| Experimental | `TEST`/`LAB_ONLY`のみ。国内実運用可能と表示しない |
| Field Pilot | production credential provisioning、session RFC、nonce fault test、TxPermit完全経由、対象SKU/profile実測、外部証跡 |
| Production candidate | 独立security review、法規・認証担当の確認、profile approval audit、24h soak |

Fableにはsecurity/complianceの正当性判定を依頼しません。Fableには、operatorが状態やprofileを誤解しないかという人間向け表現だけを確認します。

## Production radio実装前に残るblocker

次はM1a transaction kernelの着手blockerではありません。M5 physical radio実装またはField Pilotへ進む前に解消します。

- 対象radio module/SKU、認証番号・範囲、antenna、設置条件
- Japan profileの具体的channel、power、LBT、airtime、休止値
- Attachment handshake / KDF transcript
- root credential storageとsecure element要否
- RegulatoryProfile signer、配布、revocation
- ledger checkpoint方式とmulti-radioのledger単位
