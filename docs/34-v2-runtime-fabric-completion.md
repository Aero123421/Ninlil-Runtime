# 34. V2 Runtime Fabric Completion Contract

状態: **Proposed — Normative candidate / docs-only**  
提案日: 2026-07-28  
対象: Portable Core、Host Runtime、Wi-Fi bearer、Relay、Multi-parent、
bounded fragmentation/reassembly、durable custody、OSS 1.0 release

## 1. 目的

本章は、Ninlil Runtime Fabricを「100%完成」と呼ぶための共通exit contractを定義する。
行数、テスト件数、概算パーセントでは完成を判定しない。機能ごとに仕様、version、
bounded resource、実装、故障試験、実機evidence、利用者文書を閉じる。

本章は次を再定義しない。

- [30章](30-r6-secure-radio-wire.md)の`wire_profile_id=0x11`、NRW1 byte layout、
  security、LINK/FRAG、route terminal、resource table
- [U5](25-u5-cell-operating-assignment.md)のprivate control protocol v2 assignment
- [U6](26-u6-transport-custody.md)のsingle-frame OFFER/ACCEPT/REJECT/BUSY、
  dual FULL ordering、COMMIT_UNKNOWN
- [06章](06-versioning-and-compatibility.md)の独立version domain原則

本章またはADR-0017〜0021と上記Accepted contractが矛盾する場合、既存Accepted contractを
優先し、本章側を修正する。本章は関連ADRがAcceptedになるまで実装開始の根拠ではなく、
Proposed completion trancheである。

## 2. 完成の10段階条件

ある機能を`100%`、`complete`、`supported`と表記するには、次の10段階をすべて満たさなければ
ならない。未達段階を隠して平均パーセントへ丸めてはならない。

| Gate | 必須evidence |
| --- | --- |
| C1 Scope | 対象、非対象、failure domain、owner、SLOをNormative文書に固定 |
| C2 Decision | 相反案、依存方向、互換性をAccepted ADRで決定 |
| C3 Version | ABI、wire、storage、capability negotiation、migrationを割当 |
| C4 Bounds | RAM、durable storage、queue、timer、retry、airtime、concurrency上限とexhaustion動作を固定 |
| C5 Portable | heap/VLA非依存のbounded Coreまたは参照modelを実装し、unknown inputをfail-closed |
| C6 Host | POSIX参照実装、独立oracle、golden/property/fuzz、crash/restart matrixを完走 |
| C7 Target | ESP32-S3 portを実装し、pinned toolchainでtarget compile/linkとtarget-executed testを完走 |
| C8 HIL | 対象実機、物理transport、電源断、長時間soakを再現可能な手順とartifactで証明 |
| C9 Compatibility | old/new mixed version、upgrade、rollback、schema migration、unsupported拒否を証明 |
| C10 Release | public docs、example、diagnostics、support matrix、SBOM、署名、required CI、独立reviewを完走 |

次はC7またはC8の代替ではない。

- host simulator
- ESP target compile/linkのみ
- mocked RF、mocked Wi-Fi、loopback USB
- テスト件数の増加
- 設計上可能という説明

## 3. Completion claim

release manifestは機能ごとに次のclosed stateを持つ。

```text
UNALLOCATED
PROPOSED
SPEC_ACCEPTED
HOST_CANDIDATE
TARGET_CANDIDATE
HIL_VERIFIED
RELEASE_SUPPORTED
```

状態の飛び越しは禁止する。`RELEASE_SUPPORTED`だけを100%完成と表示できる。
法規適合、RF SLO、特定地域でのfield readinessはRuntime機能完成とは別のclaimであり、
外部確認と現場evidenceなしに導出しない。

## 4. Version domain allocation

以下はV2 trancheの候補割当である。ADR-0017〜0021のAccepted前にpublic header、wire byte、
durable schemaへ実装してはならない。

| Domain | 現行 | V2候補 | 規則 |
| --- | --- | --- | --- |
| Runtime release | `0.x` / V1 LAB | `1.0.0` | C1〜C10とM11を満たしたreleaseだけ |
| Runtime Platform C ABI | `NINLIL_ABI_VERSION=0x0001`、単一Bearer | 不変 | `platform.h`をBearer配列へ変更しない。Fabric Bearerを1 logical bearerとして渡す |
| Public Fabric API | 未割当 | Fabric API version 1候補 | 新opaque Fabric/packet-link/path-policy API。Runtime ABIと独立version |
| Public data wire | 未割当 | 未割当のまま | bearer framingやNRW1をpublic application wireと誤認しない |
| Secure radio wire | `wire_profile_id=0x11` | 不変 | [30章](30-r6-secure-radio-wire.md) exact profile。変更時は新profile ID |
| NCL1 envelope | `logical_version=1` | 不変 | control catalog versionと番号空間を共有しない |
| Private control | v2 | v2不変 + multi-frameはv3 | v2 catalogへmessage typeをsilent追加しない |
| Wi-Fi bearer framing | 未割当 | `NWB1 framing version 1`候補 | exact byte specとKAT受入時に初めて割当確定 |
| Foundation storage | schema 1 | schema 1不変 | 既存recordを再解釈しない |
| ESP physical store | format 4 | format 4不変 | 新namespaceを既存header意味変更に使わない |
| Bearer registry store | 未割当 | schema 1候補 | bearer identity、policy revision、availability epoch |
| Route store | NRW1 route record semantics | schema 1候補 | Controller management record、materialized docs/30 exact route record、R2 clock sidecar、drain stateを区別 |
| Parent assignment store | 未割当 | schema 1候補 | owner fence、parent set revision、`e2e_context_id/key_generation/e2e_security_id+epoch/binding` |
| Durable transfer store | `ninlil.ctl.v1`内U5/U6 logical kinds | 同じ`ninlil.ctl.v1`内のv3 logical record kinds候補 | 新physical namespaceを作らずkey-space分離。namespace hard max 4/default 2、全control key hard max 32を維持 |

各schemaはmagic、schema、record length、canonical encoding、CRC/MAC要否、generation、
maximum countを持つ。未知schema、途中migration、旧binaryによる不可逆schema openは明示拒否する。
in-place field reinterpretationとbest-effort downgradeは禁止する。

## 5. Fabric Bearer registryとpath selection

正本候補は[ADR-0017](adr/0017-bearer-registry-path-selection.md)とする。

- Runtimeの`platform.h`単一Bearer contractは維持する。既存fieldを配列化しない。
- 公開・portableなFabric Bearerが0個以上のpacket-link instanceをregistryとして束ね、
  Runtimeには1つのlogical bearerとして渡る。
- packet-link identityとlink kindを分離する。同一kindを複数登録できる。
- descriptorはmaximum frame/transfer、direction、latency class、cost、sleep compatibility、
  local unicast/broadcast、reservation、regulatory binding、availability epochに加え、
  immutable `security_profile_id`、authenticated peer/Attachment binding digestとauthority、
  integrity、confidentiality、replay protection、session freshness、custody、evidence capabilityを
  公開する。
- registry、path list、metrics、configurationはRuntime Platform ABIではなくFabric APIで公開する。
- path policyはservice/traffic classのimmutable revisionとしてadmission時にsnapshotし、
  policy identity/revision/digestと選択結果をlogical envelopeへ固定する。
- availability snapshotはdescriptor digest、security attestation state/digest/epoch、
  authenticated peer runtime、Attachment authority/bindingを含む。未知、期限切れ、未attest、
  admission要求を満たさないsecurity/custody/evidence capabilityのlinkはineligibleとする。
- admission recordはdescriptor/security/availability/path-policy snapshotをcopy-ownし、
  retry時に暗黙upgrade/downgradeしない。
- retryごとにattempt identityとselected bearer/pathを記録する。同一transactionの別path再送を
  新transactionとして扱わない。
- bearer消失は成功へ変換せず、代替pathがpolicyとdeadlineを満たす場合だけ再選択する。
- compliance permitをBearer abstractionで迂回しない。物理RF送信は既存sole authorityを通す。

### 5.1 Fabric Logical Envelope v1

現POSIX loopbackの`sizeof(ninlil_bearer_message_t)`、native pointer、padding、host endianを
直列化する形式はportable wireではなく、V1 LAB fixtureに限定する。Fabric implementationは
raw C structをprocess、compiler、architecture、transportの境界へ送ってはならない。

Fabric Logical Envelope v1（`NFL1`）をportable canonical logical packetのProposed正本とする。
これはNinlil public application data wireでもNRW1 radio frameでもない。Wi-Fi/USB byte-streamは
NFL1をtransport packetとして運ぶ。

compact radio用logical envelopeとNFL1↔NRW1 mappingは**未定義**である。別のNormative byte
layout、全6 message kindの完全な双方向mapping、lossless/unsupported規則、KATをAccepted ADRで
freezeするまで、LoRa adapterはNFL1のsend/receiveを禁止する。full NFL1 bytesをNRW1へ運ぶ方式を
defaultにせず、NRW1 `0x11`のbyte/profileも変更しない。

全整数はunsigned big-endian。IDとdigestは記載順のopaque byte列とする。固定headerは
**584 bytes**、最大packetは**2048 bytes**、v1 payloadはRuntime public logical maximumと同じ
**1024 bytes以下**、evidenceは**128 bytes以下**、各text IDは**63 bytes以下**である。
最大構成は`584 + 63*3 + 1024 + 128 = 1925 bytes`で上限内に収まる。

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | magic ASCII `NFL1` |
| 4 | 2 | version = 1 |
| 6 | 2 | header_length = 584 |
| 8 | 4 | total_length |
| 12 | 4 | CRC32C |
| 16 | 4 | message_kind |
| 20 | 4 | message_flags |
| 24 | 16 | transaction_id |
| 40 | 16 | attempt_id |
| 56 | 16 | event_id |
| 72 | 16 | source.runtime_id |
| 88 | 16 | source.application_instance_id |
| 104 | 16 | source.local.device_id |
| 120 | 16 | source.local.installation_id |
| 136 | 16 | source.local.site_domain_id |
| 152 | 8 | source.local.binding_epoch |
| 160 | 8 | source.local.membership_epoch |
| 168 | 4 | source.local.flags |
| 172 | 16 | target.target_runtime_id |
| 188 | 16 | target.target_application_instance_id |
| 204 | 16 | target.device_id |
| 220 | 16 | target.installation_id |
| 236 | 16 | target.site_domain_id |
| 252 | 8 | target.binding_epoch |
| 260 | 8 | target.membership_epoch |
| 268 | 4 | target.flags |
| 272 | 16 | authority_id |
| 288 | 8 | authority_term |
| 296 | 4 | assignment_epoch |
| 300 | 8 | service.descriptor_revision |
| 308 | 2 | service.descriptor_digest.algorithm |
| 310 | 32 | service.descriptor_digest.bytes |
| 342 | 2 | service.schema_major |
| 344 | 2 | service.schema_minor |
| 346 | 4 | service.family |
| 350 | 2 | content_digest.algorithm |
| 352 | 32 | content_digest.bytes |
| 384 | 8 | generation |
| 392 | 16 | deadline_clock_epoch_id |
| 408 | 8 | absolute_effect_deadline_ms |
| 416 | 8 | evidence_grace_ms |
| 424 | 4 | required_evidence |
| 428 | 4 | receipt_stage |
| 432 | 4 | disposition |
| 436 | 4 | effect_certainty |
| 440 | 4 | retry_guidance |
| 444 | 4 | cancel_kind |
| 448 | 8 | retry_delay_ms |
| 456 | 16 | evidence_time.clock_epoch_id |
| 472 | 8 | evidence_time.now_ms |
| 480 | 4 | evidence_time.trust |
| 484 | 16 | route_policy_id |
| 500 | 8 | route_policy_revision |
| 508 | 2 | route_policy_digest.algorithm |
| 510 | 32 | route_policy_digest.bytes |
| 542 | 16 | selected_path_id |
| 558 | 8 | path_selection_epoch |
| 566 | 4 | route_flags = 0（v1 reserved） |
| 570 | 2 | namespace_id_length |
| 572 | 2 | service_id_length |
| 574 | 2 | schema_id_length |
| 576 | 4 | payload_length |
| 580 | 4 | evidence_length |

固定header直後のvariable bodyは`namespace_id | service_id | schema_id | payload | evidence`
の順で連結する。`total_length`は584と5領域のlength合計に完全一致し、trailing byteは禁止する。
CRC32Cはreflected Castagnoli polynomial `0x82F63B78`、initial `0xffffffff`、
final XOR `0xffffffff`を用い、offset 12..15を0としてpacket全体を計算する。

decoderはmagic、unknown version、header length不一致、上限超過、integer overflow、総length不一致、
CRC不一致、unknown/invalid enum、source/target identity flag外bit、non-zero route_flags、
意味上必須のzero ID/digestをfail-closedで拒否し、失敗出力を全zeroにする。
`message_flags`はv1で0のみとし、non-zeroを拒否する。
version 1でunknown fieldをskipする拡張は禁止する。

encoderは入力viewをcall中だけborrowし、出力はcaller提供のbounded bufferへcopyする。
decoderはcaller提供workspaceへ全variable領域をcopy-ownし、入力bufferへのpointerを保持しない。
invalid argumentではcaller-visible出力、workspace、required-size出力を一切変更しない。
argument validation後のdecode failureではout envelopeと全out viewをall-zeroにするが、
workspaceのbyteとused lengthは変更しない。BUFFER_TOO_SMALLだけはexact required workspace sizeを
返し、out envelopeはall-zero、workspaceは不変とする。成功時だけworkspaceへcopyしてout viewを
publishする。heap、VLA、native struct copy、unaligned cast、pointer値、padding byteは禁止する。
clearは所有領域とsecret相当metadataをzero化する。
`abi_version`、`struct_size`、全`reserved_zero`はwireへ載せず、decode成功時にlocal ABIの値と0を
初期化する。

### 5.2 Message-kind required/zero matrix

NFL1 v1は[12章 §5.4](12-foundation-abi.md)と
[14章「Message kind, orientation, and reply-binding vectors」](14-foundation-ports-and-simulator.md)の
6-kind matrixをbyte表現へ写像する。次の`E`はoriginal admitted APPLICATIONとexact echo、
`R`はkind固有required、`Z`はall-zero/emptyを意味する。

全kind共通で`message_flags=0`、transaction/source/target/service/content digest/family/
required evidence/deadline bindingは`E`、attempt IDはnon-zeroである。
`authority_binding = {authority_id, authority_term, assignment_epoch}`はclosed groupとし、
**ABSENT**（3 fieldすべてzero）または**BOUND**（3 fieldすべてnon-zero）だけを許可する。
mixed zero/non-zeroはrejectする。BOUNDはassignment/owner-governed downlink、またはservice/path
policyが要求するflowで必須とする。ABSENTはcontrollerless/local/directを明示許可した
service/path policyでadmissionされたflowだけに許可する。必要なBOUNDがない場合は
admission/send/deliveryを0とする。

reverse kindはtriggering APPLICATION **attempt**のauthority bindingをbit-exactにechoする。
owner/assignment failoverはtransaction IDを維持し、新attempt IDとnew BOUND groupを用いる。
EventFactはevent ID non-zero/generation 0、DesiredStateCommandはevent ID zero/generation
non-zeroである。orientationとattempt echo/new規則も12/14章のexact規則に従う。

| Kind | Payload | Receipt stage / evidence / time | Disposition tuple | Cancel kind |
| --- | --- | --- | --- | --- |
| `APPLICATION` | admitted payload `E`（0..1024） | `Z / Z / Z` | `NONE/NONE/NEVER/0` | `Z` |
| `RECEIPT` | `Z` | supported non-zero `R` / 0..128 / valid time `R` | `NONE/NONE/NEVER/0` | `Z` |
| `DISPOSITION` | `Z` | `Z / Z / Z` | 12章§7.2のexact tuple `R` | `Z` |
| `CANCEL_REQUEST` | `Z` | `Z / Z / Z` | `NONE/NONE/NEVER/0` | `Z` |
| `CUSTODY_ACCEPTED` | `Z` | `Z / Z / Z` | `NONE/NONE/NEVER/0` | `Z` |
| `CANCEL_RESULT` | `Z` | `Z / Z / Z` | `NONE/NONE/NEVER/0` | known non-zero result `R` |

`CANCEL_REQUEST/CANCEL_RESULT`はDesiredStateCommandだけ、`CUSTODY_ACCEPTED`はApplication
Receiptではない。kind未使用のID、enum、time、payload、evidenceを推測・省略せず`Z`とする。
minimum-valid KATは各kindで必要fieldをvalid値にし、optional/unused fieldだけをzeroにする。
invalidな「all-zero message」をpositive KATと呼ばない。

path policy record本体はFabric registryが保持する。NFL1はadmission時にsnapshotした
`route_policy_id + revision + digest`と、attemptごとの`selected_path_id +
path_selection_epoch + route_flags`を固定する。受信側はpolicy digest衝突、non-zero route_flags、
同一attemptで矛盾するselection metadataを拒否する。

1024 bytesはNFL1 logical packet上限であり、U6 single-frame 926-byte上限ではない。
各packet-linkは自身のMTUに基づき、対応するversioned fragmentationへ写像するか明示拒否する。
将来のBoundedTransfer全体を1個のNFL1へ格納しない。1024 bytesを超えるlogical transferは
新NFL versionまたはADR-0021のstream/chunk mappingを別途freezeする。

## 6. Wi-Fi bearer

正本候補は[ADR-0018](adr/0018-wifi-bearer.md)とする。

- Wi-Fiはmanagement bulk専用という固定roleではなく、policyで許可されたdata/controlの
  transportになれる。
- credential、association、IP reachability、peer session、Ninlil attachmentを別状態として扱う。
- socket connectをcustody、Application Receipt、peer identityの証拠にしない。
- framing、peer authentication、replay/session binding、partial I/O、reconnect、backpressure、
  MTU、keepalive、sleep動作をexact specで閉じる。
- Wi-Fi断によりLoRa/local safety pathを停止してはならない。逆に、LoRa fallbackがdeadline、
  payload size、regulatory budgetを満たせない場合は明示拒否する。

## 7. Relay

正本候補は[ADR-0019](adr/0019-route-relay.md)とする。

Relay byte/security semanticsは[30章](30-r6-secure-radio-wire.md)を唯一の正本とする。
本trancheはroute authority、install、lease、drain、queue、diagnostics、recoveryを接続する。

- Controllerだけが`authority_id + controller_term + route_revision`でfenceされたmanagement/install
  recordを発行する。これは[30章](30-r6-secure-radio-wire.md)のexact NRW1 route recordそのものではない。
- install ownerはmanagement recordから、docs/30の`egress_peer_id`、
  `egress_hop_context_id`、`egress_route_handle/generation`、`authority_id/lease_epoch/expiry`、
  `grant/queue_quota`、`max_hops`、`ack_policy`を全field atomic materializeする。
  別名`route_epoch`は設けず、management lease epochとNRW1 `lease_epoch`を同一値にする。
- exact route recordにはR2 `{clock_epoch_id, expiry_ms}` sidecarをatomicにbindする。
  authority/clock epoch不一致ではACTIVE 0、forward 0、radio TX 0とする。
- Relayはouter Hopを認証し、E2E payloadを開かず、bit-identical E2E envelopeを再wrapする。
- unknown、expired、loop、wrong direction、wrong terminal、draining新規itemをfail-closedにする。
- forwarding queue、per-route inflight、airtime、retryはfinite reservationを必要とする。
- planned drainではdrain fenceより前にadmit済み、同一route revision、immutable drain deadlineと
  lease deadlineの早い方より前に完了可能なinflightだけを許可する。新規admissionは0、
  deadline到達後はforward/TX 0。sudden failureと分け、alternate routeなしをsuccess表示しない。

## 8. Multi-parent

正本候補は[ADR-0020](adr/0020-multi-parent.md)とする。

- uplink receive diversityとdownlink ownershipを別機構とする。
- uplinkは複数parentで受信でき、Controllerがtransaction/attempt identityでdeduplicateする。
- downlink sealerは
  `{authority_id, controller_term, assignment_epoch, owner_controller_id, owner_cell_id,
  direction, e2e_context_id, key_generation, e2e_security_id, e2e_security_epoch,
  e2e_binding_digest}`でfenceされた1 ownerだけとする。
- owner変更は、new contextをINACTIVEでFULL install → old ownerのfresh-seal fenceをproofまたは
  lease expiry付きでFULL → new assignment+contextをatomic ACTIVE → traffic switch → old retireの
  順とする。旧ownerがseal済みで未送信のblobは送信せず、same transaction/new attemptでnew
  contextへ再prepareする。既送信blobだけをbounded receive-only retirement/dedupe対象にする。
- redundancy profileとcapacity split profileを別にし、同じSLOを暗黙保証しない。
- split brainまたはowner不明時のdownlink sealは0件でなければならない。

## 9. Fragmentation、reassembly、durable custody

Radio fragmentation/reassemblyは[30章](30-r6-secure-radio-wire.md)のFRAG_START、CONT、
FRAG_ACK、resource table、commit orderingをそのまま実装する。`wire_profile_id=0x11`を
変更しない。

Transport multi-frame custodyは[ADR-0021](adr/0021-multi-frame-durable-custody.md)の
別version domainとする。唯一のcarrierはnegotiated private control protocol v3 catalogの
NCL1 `logical_version=1` over NCG1 `DATA (0x03)`であり、NFL1/NWB1 application packetへ
載せない。U6 v2はsingle-frameのまま維持し、次を禁止する。

- v2 OFFER payloadを暗黙にfragment manifestへ再解釈する
- RAM reassemblyだけでACCEPTを返す
- 一部chunk受領をApplication Receiptまたはtransfer成功にする
- reconnect後に証拠のないoffsetから再開する
- 998-byte bodyへ収まらないdigest listを単一manifestへ詰める

multi-frame成功は、受信側の全chunk検証済みmanifestと再構成結果がFULL、受信側ACCEPTがFULL、
送信側受領記録がFULLになった後だけ成立する。正確なlinearizationとCOMMIT_UNKNOWN recoveryは
ADR-0021受入後のNormative byte/storage specで固定する。manifestはbounded paged形式を必須とし、
page count/entry count/chunk count/chunk size/total sizeと全v3 message ID/layoutをfreezeする。
Accepted前に[06章](06-versioning-and-compatibility.md)、[23章](23-usb-radio-boundary.md)、
[25章](25-u5-cell-operating-assignment.md)、[26章](26-u6-transport-custody.md)を同一changeで更新・
re-freezeしなければならない。

## 10. Bounded resource contract

すべての上限はprofile作成時に検証し、Runtime開始後にheap成長で補ってはならない。
上限超過時は既存予約を破壊せず、structured BUSY/REJECTまたはparked retryを返す。

| Resource | 必須bound | exhaustion時 |
| --- | --- | --- |
| Bearer instances | 登録数、instanceごとのqueue | 新規登録/予約を拒否 |
| Path candidates | serviceごとの候補数、再選択回数 | policy mismatchまたはdeadline failure |
| Wi-Fi sessions | peer数、RX/TX frame、byte budget、partial parser | backpressure後にsession close。成功非主張 |
| Routes | route record、lease、children、forward queue | route installまたはforwardを拒否 |
| Parents | discovered/eligible/active parent数 | deterministic scoreで上限内だけ保持 |
| Radio fragments | [30章](30-r6-secure-radio-wire.md)のfragment/reassembly/tombstone上限 | 同章のexact fail-closed動作 |
| Durable transfers | manifest、chunks、bytes、concurrent transfer、resume attempts | BUSY/REJECT。partial apply禁止 |
| Retry | family/service/bearerごとのattempt・deadline・airtime | terminal outcomeまたはparked retry |
| Diagnostics | event ring、per-bearer/route counters | oldest diagnosticのみ規定に従いdrop。control stateはdrop禁止 |

exact数値はHardware/Runtime profileに置き、compatibility matrixとmachine-readable capabilityへ
出力する。host defaultをESP profileへ暗黙転用しない。

## 11. Acceptance matrix

| Slice | Portable/Host必須 | Fault/compatibility必須 | ESP/HIL必須 |
| --- | --- | --- | --- |
| Core/API/storage | 全public API contract、independent model、全write-point crash、restart | ABI old/new、schema migration、corrupt/unknown schema | target conformance、power-cut |
| Bearer registry | 2種3 instance、policy/security snapshot、fairness、deadline | loss、availability/security attestation epoch race、hot unregister、old ABI | Wi-Fi実経路。LoRa同時稼働は別compact mapping Accepted後 |
| Wi-Fi | 2 process E2E、partial read/write、backpressure、10,000 message | auth failure、disconnect/reconnect、peer restart、mixed framing | ESP32-S3実AP、強制切断、sleep/wake、24h soak |
| NRW1 FRAG | exact KAT、2〜16 fragment、loss/reorder/duplicate/conflict、fuzz | resource exhaustion、timer edge、tombstone、restart規則 | 2実機RF、loss injection |
| U6 single-frame | dual FULL、全write-point crash | COMMIT_UNKNOWN、duplicate OFFER/ACCEPT、reconnect | USB/TCP実経路、power-cut |
| Multi-frame custody | manifest/chunk/reassembly oracle、partial apply 0 | 各chunk/ACK/commit crash、resume conflict、v2拒否 | 実transport、送受信電源断 |
| Relay | 2〜3 hop simulator、loop/stale lease/drain | relay/Controller restart、sudden failure、queue exhaustion | 3 RF実機、24h soak |
| Multi-parent | duplicate uplink、single-owner downlink、migration | split brain、parent/backhaul loss、old context replay | 2 parent + 1 Endpoint実機 |
| OSS release | clean Linux/macOS build/install/use、docs/link/API lint | N-1 matrix、artifact install、rollback | release packageからESP sample build/flash |

acceptance artifactにはcommit SHA、toolchain、profile、seed、実機識別子、試験時間、raw result、
failure injection pointを含める。手動要約だけを証拠にしない。

## 12. 依存順

```text
ADR-0017 + Fabric API/storage allocation
  -> bounded Fabric Bearer / Scheduler
     -> ADR-0018 Wi-Fi bearer -----------+
     -> NRW1 LINK/FRAG implementation ---+--> ADR-0019 Relay
     -> normative U6 single-frame -------+       -> ADR-0020 Multi-parent
     -> ADR-0021 multi-frame custody ----+
                                             -> M10 Field Pilot
                                             -> M11 OSS 1.0
```

- M1a restart-safe transaction kernelとM3 durable storage gateを迂回しない。
- RelayはNRW1 LINK/FRAG、route storage、schedulerの後に実装する。
- Multi-parentはRelayとsingle-owner fencingの後に実装する。
- Wi-FiとNRW1 LINK/FRAGは共通Bearer RegistryのAccepted後、並行実装できる。
- multi-frame custodyはU6 single-frame conformanceを弱めず、別versionとして並行実装できる。

## 13. Compatibilityとmigration

1. Runtime Platform ABI v1と単一Bearer slotを維持する。既存利用者にpacket-link registryを要求しない。
2. Fabric Bearerは既存Bearer vtableを実装する1 logical bearerとして接続する。
3. Fabricがlegacy packet-link adapterを包む場合、descriptorにない能力はunsupportedとし、推測しない。
4. rolling upgradeはController、Cell Agent、mains-powered Endpoint、sleepy Endpointの順とする。
5. route/parent schema migration中は該当downlinkをfenceする。旧ownerへfallbackしない。
6. multi-frame非対応peerにはU6 v2 single-frameだけを提示し、payloadが収まらなければ明示拒否する。
7. NRW1 `0x11`のbyte、timer、resource意味を変更する実装は新profile IDなしに受理しない。
8. Wi-Fi framing version不一致をraw byte streamやNCG1へsilent fallbackしない。

## 14. OSS 1.0 release gate

C1〜C10に加え、次をrequired CIまたはrelease checklistで証明する。

- requirements traceabilityに`partial`と未所有のpublic symbolが0
- Linux/macOS Debug/Release、GCC/Clang、ASan/UBSan
- public ABI diff、old/new consumer compile/link、mixed-version E2E
- storage migration crash matrix、fuzz/property、static analysis
- documentation link/lint、example build、package install
- dependency/license、SBOM、source provenance、release署名
- compatibility matrixと実CI targetの一致
- 外部開発者が非公開repositoryや個別製品知識なしでport/exampleを完走

## 15. 非主張

本Proposed文書とADR-0017〜0021を追加しただけでは、次を主張しない。

- Fabric API version 1、NFL1、NWB1、control v3、各storage schemaの割当確定
- Wi-Fi driver、TCP/UDP session、physical RF、Relay、Multi-parent、FRAGの実装
- U6 dual FULL conformance、multi-frame resume、ESP power-cut成功
- RF距離、50/100 node SLO、battery life、Japan legal、技適、field readiness
- security review、HIL、soak、1.0 release、production support

compile/link、host simulation、docs freeze、Proposed ADRは上記claimの代替ではない。

## 16. 関連ADR

- [ADR-0017: Bearer Registry and Path Selection](adr/0017-bearer-registry-path-selection.md)
- [ADR-0018: Wi-Fi Bearer](adr/0018-wifi-bearer.md)
- [ADR-0019: Route Authority and Relay Lifecycle](adr/0019-route-relay.md)
- [ADR-0020: Multi-parent Ownership and Failover](adr/0020-multi-parent.md)
- [ADR-0021: Multi-frame Durable Custody](adr/0021-multi-frame-durable-custody.md)
