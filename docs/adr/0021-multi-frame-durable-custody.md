# ADR-0021: Multi-frame Durable Transfer and Custody

状態: **Accepted baseline / Application-handoff amendment SPEC_ACCEPTED**
状態補足: 2026-08-01のSPEC_ACCEPTED baselineは履歴として維持する。本文の
Application-handoff amendment（MFN1 admission profile revision 2、改訂OPEN、Foundation
handoff）は独立限定re-reviewで**P0=0 / P1=0 / P2=0**を確認し、
**SPEC_ACCEPTED normative amendment**とする。
2026-08-02のdeadline sentinel erratumは、改訂OPENのdeadline shapeを既存Foundation
canonicalへ一致させる狭い訂正であり、original Applicationからのbit-exact転記、
admission profile revision、wire field、公開APIを変更しない。
提案日: 2026-07-28  
候補修復日: 2026-07-29  
SPEC_ACCEPTED日: 2026-08-01  
Application-handoff amendment SPEC_ACCEPTED日: 2026-08-01  
Deadline sentinel erratum日: 2026-08-02  
RELEASE_SUPPORTED日: —

## Context

[U6](../26-u6-transport-custody.md)と[ADR-0006](0006-u6-transport-custody.md)はprivate
control protocol v2のsingle-frame custody、dual FULL、COMMIT_UNKNOWNを固定し、
fragmentation/multi-frame resumeを対象外にしている。一方、1024-byte logical packetや
packet-link MTUを超えるBoundedTransferには、bounded chunk、再開、全体digest、
partial apply防止が必要である。

独立auditは現行Proposed草案をNO-GOとした。主因は次である。

1. U5/U6は`selected_control_version == 2` exactを要求するが、破棄済みの
   selected-control-value-3 inheritance草案は
   `selected == 3`でU5/U6を再利用すると主張し、closed catalogが衝突する。
2. キャリアはNCG1/NCL1しかなく、generic Fabric/NFL1とcompact RF/Wi-Fiのmappingが未定義。
3. custody / abort / expiry、zero/final/terminal、publication owner、resource/DoS、
   compatibility / default-OFF / rollbackが不完全。
4. `80 FULL/day`仮定は最大サイズ転送のper-chunk FULL会計と物理的に両立しない。
5. machine vector / independent gateが無い。

本ADRの2026-08-01 baselineはproduct-neutralなSPEC_ACCEPTED design authorityである。
その後に見つかったApplication cold-restartの欠落を閉じるため、本現行版は
改訂OPENとFoundation handoffをSPEC_ACCEPTED normative amendmentとして追記する。
private/default-OFF software candidateは存在するが、本amendmentのimplementation complete、HIL、
`RELEASE_SUPPORTED`は主張しない。

## Decision

1. **Logical ApplicationDataとtransport chunkを分離する。**  
   ApplicationDataは上位がcustodyする整列済みbyte列（0..32768）である。transport chunkは
   そのApplicationDataをboundedに運ぶstorage/wire単位であり、Radio FRAGやNFL1 frameと
   同一ではない。partial chunk、RAM reassembly、bearer success、Radio FRAG_ACKを
   Application Receiptやtransfer completeにしない。

2. **U6 v2 single-frameは変更しない。** multi-frameはprivate **MFDT v1**の
   別closed catalogとする。Accepted HELLO version domainやv2 message typeへ
   silent追加しない。

3. **version allocation（exact）**  
   HELLO bodyは8 bytesのまま。Accepted control version domainは変更せず、
   `min_control_version` / `max_control_version`と`selected_control_version`は
   **1または2だけ**である。値3、0、4以上はHELLO/HELLO_ACKでrejectし、
   MFDT対応可否をcontrol versionから推測しない。

   **Private MFDT negotiation domain (independent of Accepted HELLO selected 1/2):**

   | domain | rule |
   | --- | --- |
   | Accepted HELLO selected_control_version | **exact 1 or 2 only** (docs/23·25·26 freeze byte-exact; **no re-freeze**) |
   | private_mfdt_admission_v2 | separate from selected_control_version; requires local policy ON + private capability bits + session_generation bind |
   | MFDT messages 0x34..0x43 | private candidate only; never silent-added to v2 catalog |
   | U5/U6 wire bodies | bit-exact Accepted v2; unchanged under MFDT |

   - **Forbidden:** claiming selected=3 includes U5/U6 inheritance against Accepted freeze.
   - **Forbidden:** editing docs/23·25·26 for this candidate.
   - MFDT admissionはactive control session上のprivate `MFN1` OFFER (`0x34`) /
     ACCEPT (`0x35`) transcriptでのみ成立する。base `selected_control_version`は
     exact 1または2のまま変化しない。
   - mixed versionはfail closed: MFN1 admission profile revision 2未成立、revision 1/2混在、
     policy/capability/carrier不一致、
     session generation/cookie不一致なら`0x34..0x43`を業務解釈しない。
   - MF-O01はbaseline revision 1がSPEC_ACCEPTEDだった履歴を保つ。改訂OPENを認識する
     revision 2はMF-O09でSPEC_ACCEPTEDとする。これは実装・release supportの根拠にしない。

4. **carrier mapping（exact）**

   | carrier | multi-frame control carriage | ApplicationData relation | status |
   | --- | --- | --- | --- |
   | NCG1 `DATA (0x03)` + NCL1 `logical_version=1` | sole accepted control carrier candidate | control only; ApplicationDataはchunk payloadとして運ぶ | **MAPPING_CANDIDATE** |
   | Generic Fabric packet-link | exact private Foundation owner-plane envelope（下記）にNCL1 bytesを載せる | Fabric outer may admit ApplicationData that **requires** multi-frame; transfer itself is NCL1 custody, not NFL1 fragmentation | **MAPPING_CANDIDATE** (implemented private/default-OFF) |
   | ordinary public NFL1 application service | raw/untyped control/custody message禁止 | ApplicationData identity/digest/deadline may be **bound** into TRANSFER_OPEN; public Service registrationはmulti-frame controlを運ばない | **BOUND_ONLY** |
   | Compact RF NRW1 `wire_profile_id=0x11` | multi-frame control mapping | — | **MAPPING_UNAVAILABLE** |
   | Wi-Fi NWB1 | multi-frame control mapping | — | **MAPPING_UNAVAILABLE** |

   MAPPING_UNAVAILABLE carrierだけしか無いendpointは、ApplicationDataがU6 single-frame上限
   （926 bytes）を超える場合`REJECT unsupported version/profile (code=4)`する。
   compact RF/Wi-Fiのdirect/bypass mappingは**別accepted mapping ADR**が来るまで開かない。
   Generic Fabric mappingをconforming Wi-Fi/RF packet-linkが運ぶ場合も、下記のFoundation
   envelopeを変更しない。physical bearer HILの成功をこのsoftware mappingから推論しない。

   **Generic Fabric owner-plane envelope（exact private candidate）**

   | field | exact value / derivation |
   | --- | --- |
   | Foundation `message.kind` | `APPLICATION`。MFN1/MFDT responseもpayloadが128-byte evidence ceilingを超え得るため、Receiptへ偽装しない |
   | service namespace / service / schema | `org.ninlil.private` / `mfdt-control` / `ncl1-mfdt-v1` |
   | descriptor revision / digest | `1` / `SHA-256("NINLIL-MFDT-FOUNDATION-CARRIER-V1")` |
   | schema / family | major `1`, minor `0`, `TRANSFER_RESERVED` |
   | payload | exact NCL1 DATA bytes（26..1024 bytes）。再エンコード、partial payload、evidence fieldへの移送は禁止 |
   | content digest | `SHA-256(payload)` |
   | generation | bound MFN1 `session_generation` exact |
   | transaction ID | first 16 bytes of `SHA-256("NINLIL-MFDT-FABRIC-TRANSACTION-V1" || session_generation_u32_be || session_cookie_u64_be || request_id_u32_be || min(runtime_id_A,runtime_id_B) || max(runtime_id_A,runtime_id_B))` |
   | attempt ID | first 16 bytes of `SHA-256("NINLIL-MFDT-FABRIC-ATTEMPT-V1" || transaction_id || source_runtime_id || mfdt_message_type_u8 || content_digest)` |
   | authorization | exact source/target runtime + application IDs、service identity、forward path policy、authority bindingが必要 |
   | transmission | trusted clock sample + fresh one-shot TxPermit必須。`WOULD_BLOCK/UNAVAILABLE`はoutbox ownershipを維持、`LOST_UNKNOWN`はCOMMIT_UNKNOWNとしてfail closed |
   | ingress | service/source/target/session generation/cookie/content digestを全検証し、transaction IDとattempt IDを上記domainから再導出してbit-exact一致を確認してからcopy-own。foreign/non-canonical/invalid messageをMFDTへ渡さない |

   `TRANSFER_RESERVED`はpublic application Serviceとしてregisterできない。上記はprivate
   owner-plane demux専用であり、application固有語彙をCoreへ追加しない。

5. **manifest / chunk / receipt / abort / completion / reassembly / custody / application receipt**
   のsemanticsを本ADR §MFDT v1 private candidate exact profileと
   machine vector `spec/vectors/multi-frame-durable-transfer-spec-v1.json`で固定する。

6. **publication ownerはreceiver multi-frame owner唯一。** sender、relay-neutral bearer、
   Radio FRAG、Controller assignment、Fabric path selectorはpublication/prepareを行わない。

7. **resource / DoS / FULL budget**はper-chunk FULL durabilityを弱めず、不可能な
   `80 FULL/day`仮定を廃止し、exact FULL group会計へ置換する（§Foundation FULL budget）。

8. **default-OFF / rollback**: multi-frame admissionはlocal policy default OFF。
   MFN1 transcriptだけではなくlocal policy/capability/carrierの全条件を要求する。
   rollbackはin-flight完了/abort後にMFDT policy OFFとして新しいcontrol sessionを確立する。
   MFDT recordのU6 v2変換はしない。

9. machine authorityは **4系統** で固定する: generator / independent Python gate /
   independent Node gate / independent C11 gate（literal byte KAT）。
   CMakeにはSPEC_ACCEPTED design focused tests **10本**を登録済み（実装完了・HIL・
   public ABI・RELEASE_SUPPORTEDを主張しない）。compatibility matrix、README、ADR indexは
   本昇格へ同期するが、他ADR実装やmulti-frame production supportは昇格させない。

10. **MFDT durable rowsはFoundation Runtime namespaceへ混在させない。**
    Foundation create/recoveryはfuture rootを含むsingle valueを4096 bytes以下に固定する一方、
    canonical `NM3S` / `NM3R`は本amendmentで最大35211 bytes、`NRC1`は15020 bytesである。
    したがってMFDT-ON Runtimeは、同じcopy済みStorage Port provider上で
    §Durable storage candidateの決定的派生namespaceを別handleとしてopenする。
    Foundation namespace scannerの4096-byte workspace、closed kind catalog、
    `BUFFER_TOO_SMALL` corruption分類は変更しない。MFDT-OFFでは派生namespaceをopenしない。
    2 namespace間のatomic commitは主張せず、pre-arm / Foundation FULL /
    restart reconciliationのclosed protocolでfalse custodyを防ぐ。

## MFDT v1 private candidate exact profile

### Logical ApplicationData vs transport chunks

```text
ApplicationData D (0..32768 bytes)
  -> canonical manifest M (transfer_id, lengths, per-chunk digests, whole digest, service bind)
  -> transport chunks C[i] = D[offset_i : offset_i + length_i]
  -> NCL1 messages over NCG1 DATA
  -> receiver durable reassembly R
  -> whole-content digest check
  -> publication_token (READY)  [receiver owner only]
  -> upper private handoff prepare(mfdt_publication_token, R)
     [mfdt_publication_token = existing private publication_token;
      never the public ninlil_delivery_token_t]
  -> application receipt / effect evidence (upper contract)
```

`mfdt_publication_token`はこの図だけの曖昧性除去用表記であり、新field/APIではない。
public `ninlil_delivery_token_t`（Foundation callback completion用）とprivate
`publication_token`（MFDT handoff/deduplication用）は別の値・別の責務である。

- `D`と`C[i]`は別概念。chunk success ≠ application receipt。
- whole-object digestは`SHA-256(D)` exact。hash treeはv1候補に採用しない
  （per-chunk SHA-256 list + whole digestで閉じる）。
- empty payload: `total_length=0`、`chunk_count=0`、`manifest_page_count=0`、
  `whole_content_sha256 = SHA-256("")`、OPEN_ACCEPTで`manifest_complete=1`、
  chunk exchangeなし、必ずTRANSFER_FINALIZE→TRANSFER_ACCEPT。
- exact-multiple final chunk: `total_length = k*896`なら最終chunk lengthはexact 896。
- 1-byte final chunk: `total_length = k*896 + 1`なら最終chunk lengthは1。

### MFN1 private admission profile revision 2 and mixed-version fail-closed

NCL1 envelope `logical_version=1`、26-byte header、998-byte body上限、NCG1
`DATA (0x03)`を変更しない。HELLO/HELLO_ACK bodyも8 bytesのまま、
`selected_control_version`はAccepted値1または2だけである。

MFDT transfer message catalogはprivate MFDT v1の`0x36..0x43`を維持するが、
改訂OPENのadmissionは別domain `private_mfdt_admission_v2`を使う。次の全条件を満たすまで
`0x34..0x43`はadmitしない。

1. local policyがON
2. 両endpointが`CAP_TRANSFER (0x01) | CAP_NCL1_DATA (0x02)`をexact提示
3. active control sessionのgeneration/cookieがnon-zeroかつheader/bodyでbit-exact一致
4. local/peer endpoint IDがnon-zero、相異、OFFER/ACCEPTで方向どおり一致
5. MFN1 OFFER/ACCEPT digestとNCL1 `request_id`相関が成功
6. carrier、chunk geometry、content上限がexact profileと一致

revision 1のOFFER/ACCEPT、revision 1 OPEN、revision 1から作成されたactive schema 1
`NM3S/NM3R`はrevision 2/schema 2へ変換しない。local/peerのどちらか一方でも
admission revisionが2でない、またはMFN1 transcriptとOPEN layout revisionが一致しない場合は
REJECT code 4、durable mutation 0でfail closedとする。自動migration、length heuristicによる
revision 1の業務解釈、in-place upgradeを行わない。

#### MFN1 type allocation

| NCL1 private message | type | NCG1 binding | body |
| --- | ---: | --- | ---: |
| `MFDT_NEGOTIATE_OFFER` | `0x34` | `DATA (0x03)` only | 112 |
| `MFDT_NEGOTIATE_ACCEPT` | `0x35` | `DATA (0x03)` only | 160 |
| MFDT transfer messages | `0x36..0x43` | `DATA (0x03)` only | message-specific |

これらはAccepted U4/U5/U6 catalogへ追加しないprivate extensionである。private demuxは
base NCL1 framingとactive session検証後にだけ実行する。

Accepted catalogの使用値はU4 `0x01..0x03, 0x10..0x12`、U5 `0x20..0x22`、
U6 `0x30..0x33`である。MFDT v1はこれらをbyte-exact維持し、highest Accepted valueの直後にある
最小の連続16値 `0x34..0x43`を選ぶ。旧Proposed草案の
`0x3e/0x3f + 0x40..0x4d`は未受入・未releaseのため互換性authorityではなく**void**である。
この再採番はAccepted peerの既知typeを変更せず、MFN1未成立peerは全値をunknownとして
fail closedにする。public allocation、control version 3、U5/U6 re-freezeは発生しない。

#### OFFER body（112 bytes）

```text
0   4   magic                 "MFN1"
4   1   mfdt_version          exact 2 (private admission profile revision)
5   1   kind                  exact 1 (OFFER)
6   2   flags                 exact 0
8   4   session_generation    u32 BE; NCL1 headerと一致、non-zero
12  8   session_cookie        u64 BE; NCL1 headerと一致、non-zero
20 16   request_nonce         caller CSPRNG; all-zero禁止
36  4   capability_bits       u32 BE; exact 0x00000003
40  4   max_content           u32 BE; exact 32768
44  2   chunk_size            u16 BE; exact 896
46  1   max_active            exact 1 (ESP) または4 (Host)
47  1   carrier_mask          exact 0x01 (NCL1 DATA)
48 16   requester_endpoint_id non-zero
64 16   responder_endpoint_id non-zero、requesterと相異
80 32   offer_digest          §digest
```

#### ACCEPT body（160 bytes）

```text
0   4   magic                 "MFN1"
4   1   mfdt_version          exact 2 (private admission profile revision)
5   1   kind                  exact 2 (ACCEPT)
6   2   flags                 exact 0
8   4   session_generation    OFFER/headerと一致
12  8   session_cookie        OFFER/headerと一致
20 16   request_nonce         OFFERをecho
36 16   responder_nonce       caller CSPRNG; all-zero/同値禁止
52  4   selected_capabilities u32 BE; exact 0x00000003
56  4   max_content           u32 BE; exact 32768
60  2   chunk_size            u16 BE; exact 896
62  1   selected_max_active   min(requester, responder)、1..local max
63  1   carrier_mask          exact 0x01
64 16   requester_endpoint_id OFFERをecho
80 16   responder_endpoint_id OFFERをecho
96 32   offer_digest          OFFERをecho
128 32  accept_digest         §digest
```

Digestは次のbyte列のSHA-256 exactである（文字列にNULを含めない）。

```text
offer_digest  = SHA-256("NINLIL-MFDT-OFFER-V2"  || request_id_u32be || OFFER[0,80))
accept_digest = SHA-256("NINLIL-MFDT-ACCEPT-V2" || request_id_u32be || ACCEPT[0,128))
```

responderはvalid OFFERからACCEPT wireをmaterializeした後にだけadmitする。
requesterはcorrelated ACCEPT検証後にだけadmitする。同じsessionで同一
`request_id + offer_digest`のduplicate OFFERはcached ACCEPTをbit-exact再送する。
異なる2つ目のOFFER、nonce/digest/identity競合はsessionをfenceし、再bindまでadmitしない。
generation/cookie変更は全transcriptを破棄し、必ずfresh MFN1を要求する。

### Fixed limits

| Item | Exact candidate |
| --- | ---: |
| maximum logical ApplicationData | 32768 bytes |
| normal chunk size | 896 bytes |
| maximum chunk count | 37 |
| manifest entry size | 40 bytes |
| entries per manifest page | 22 |
| maximum manifest pages | 2 |
| maximum active MFDT v1 transfer / ESP MFDT namespace | 1 |
| maximum active MFDT v1 transfer / Host reference profile | 4 |
| maximum resume queries / transfer / session generation | 8 |
| maximum abort generations / transfer | 8 |
| receiver reservation lifetime | 300000 ms, immutable trusted local platform monotonic epoch |
| completed/tombstone retention | 86400000 ms or explicit upper handoff policy, whichever is longer |
| NCL1 body max | 998 |
| private transfer workspace (caller-owned) | 65536 bytes per active slot |
| Host owner aggregate workspace | 280064 bytes（4 × 65536 active arena + 17920 control arena） |
| concurrent inflight multi-frame requests / session | 4 |
| CHUNK_OFFER fairness slice / peer / scheduling quantum | 1 outstanding unpaid CHUNK_OFFER |

For `total_length > 0`,
`chunk_count = ceil(total_length / 896)`、chunk `i`のoffsetは`896 * i`、lengthは
`min(896, total_length - offset)`で一意に導出する。non-final chunk lengthはexact 896である。
`total_length=0`ではchunk/page countとも0、content digestはSHA-256(empty)である。
`manifest_page_count = ceil(chunk_count / 22)`で、0..2以外を拒否する。
加減算、ceil、offset計算はchecked integerで行い、overflow時はdecode/admissionを変更せずrejectする。

#### Host four-slot owner profile（normative）

Host reference profileの`maximum active=4`は単一engineの上限を4へ書き換える意味ではない。
単一transfer engine primitiveを、次のcaller-owned coordinatorが4個保持する。

| item | exact Host rule |
| --- | --- |
| active slot count | 4、sender/receiver direction合計。slot index `0..3` |
| slot allocation | fresh OPENはlowest free slot。既存transfer IDは同じslotへroute。異なる5件目はCAPACITY/BUSY、state mutation 0 |
| restart slot allocation | 全record semantic validation成功後、active transfer IDをunsigned lexicographic ascendingに並べ、slot 0から再割当 |
| per-slot transfer workspace | 65536 bytes、8-byte aligned、slot lifetime中は他transferと共有しない |
| active coordinator metadata | 512 bytes exact（128-byte owner header + 4 × 96-byte active slot descriptor） |
| terminal catalog | 16 × 64 = 1024 bytes。retained groupのtransfer ID、peer、role、NRC1 generation、schema/replay eligibility、volatile rebindを保持 |
| control outbox metadata | 64 bytes exact。owner bind、route、frame length、ownershipを保持 |
| control outbox | NCL1 maximum 1024 bytesをexactly 1 frame copy-own |
| control NRC1 scratch | 15024 bytes（15020-byte value + 8-byte alignment padding） |
| control NM30 scratch | 184 bytes（180-byte schema-2 value + 8-byte alignment padding） |
| control recovery scratch / reserved | 88 bytes exact |
| aggregate caller-owned RAM | `4 * 65536 + 512 + 1024 + 64 + 1024 + 15024 + 184 + 88 = 280064` bytes exact |
| transaction ownership | coordinator全体でRW FULL transactionは同時1件。transferごとのFULLをserial化 |
| duplicate routing | lookup keyはtransfer ID exact。active descriptorを先に、次にterminal catalogを検索する。同じIDが両方にある場合はCORRUPT。same ID/same bindだけ同route。cross-route BIND52 responseは禁止 |
| active exhaustion | 4 slot occupied時の5件目はcontrol outboxへexact CAPACITY/BUSYをcopy-ownできた場合だけtransport `OK`。既存4 slot、cursor、store、terminal catalogを変更しない |

active 4 arenaはactive transfer専用であり、fresh pre-admission refusalまたはretained
terminal replayのscratch/outboxとして借用してはならない。512-byte active metadata、
1024-byte terminal catalog、64-byte control metadata、1024-byte control outbox、
15024-byte NRC1 scratch、184-byte NM30 scratch、88-byte recovery/reservedを合わせた
**17920-byte control arena**はcaller-owned、
8-byte aligned、startup固定であり、request処理中にheapへfallbackしない。

terminal catalog entryは64 bytes exactで、durable由来の`transfer_id[16]`、
`peer_endpoint_id[16]`、NRC1 current session generation、owner role、NM30 schema、
replay eligibilityと、volatileなfresh session cookie/bind-validを保持する。cookieはstorageから
復元せず0/bind-pendingで起動する。catalogはretained terminalをunsigned transfer ID順に
最大16件読み、activeと合わせたtracked group 16/keys 32/bytes ceilingを検査する。
17件目、duplicate ID、active+terminal BOTH、NM30/NRC1片側欠落、bind不整合は切り捨てず
fail closedとする。

recovered activeはactive OPEN由来peer/roleとactive+NRC1 generation、recovered schema-2
terminalはNM30 peer/roleとNRC1 header generationをauthorityとする。rebindはpeer、role、
generation exact一致かつfresh non-zero cookieの場合だけ成功する。一度bindしたrouteのcookie
差替えは禁止する。schema-1 terminalはreplay-ineligibleでありrebind/wire response 0だが、
canonical legacy rowとして課金しretention GCは許可する。peer/role/cookieを推測しない。

terminal ingressはactive slotを消費せずcontrol NRC1 scratchへrowをread/validateする。
`(generation, request_id)`とbody digestのexact hitだけをbit-exact replayし、digest conflictは
DUPLICATEとする。post-terminal missはSTATE responseを新しいNRC1 slotへ専用1 FULLで
保存してからexact bodyを作る（transfer-state mutation 0、NRC1 cache FULL count 1）。
control outboxへcopy-ownできた場合だけtransport `OK`とする。control outboxが未払いなら既frameを保持し、
次のterminal replay/stateless refusalは`ERR_BUSY`、slot/catalog/store/cursor mutation 0。
Host APIはcontrol route sentinel `0xff`を`slot_out`へ返し、同sentinelを
`host_take_outbound_ncl1`へ渡してdrainする。snapshotはterminal countとcontrol-outbox
pendingを公開する。

Allocation ownership boundary is closed as follows. The exact 65536-byte
transfer workspace is caller-owned **per single-transfer engine**; the Host
coordinator therefore owns four distinct workspaces and never aliases them.
Canonical active-record and NRC1 assembly scratch are fixed subregions inside
each such workspace, not process-global or separately allocated bulk. The ESP
durable read-back/staging pools and explicit spine context remain caller-owner
startup bulk outside the transfer workspace. ESP-store bind and spine init must
obtain every buffer they actually own before publishing a usable handle. After
that startup boundary, request handling, retry, restart, terminalization, and
GC perform **zero allocation attempts** and only reuse fixed owner-local bulk
under the serialized FULL owner. Startup allocation failure in an actual
allocator returns STORAGE with no usable handle, no durable mutation, and no
wire ownership. This review has no target-allocator fault-injection result:
target OOM evidence is **LOCAL_NOT_RUN** and remains required before any
release-support promotion. “Allocate on first request” remains forbidden. No
process-global allocation counter or lazy allocation seam is part of the
accepted engine contract.

The private ESP durable-store adapter state is owned by the exact
`ninlil_mfdt_v1_lab_store_t` passed to every store operation. Its Storage Port
binding/handle, current transaction handle, OLD snapshot metadata, read-back
buffer and OLD-pool pointers are never process-global. `esp_store_bind` and
`esp_store_unbind` therefore take that store owner explicitly. Rebinding or
beginning another FULL while the same owner is bound/active returns `ERR_BUSY`
before mutation; a distinct owner remains independent. Unbind rolls back an
owned open transaction and clears transaction/binding metadata while retaining
its startup bulk for an explicit rebind. Finalization zeroizes and releases the
bulk, then leaves every byte of the caller-owned store zero. Initialization is
only valid for fresh/zero or already-finalized storage; it never guesses whether
arbitrary caller bytes contain live allocation pointers. The raw last-CU class
is owner-local diagnostics, while the unavailable HIL-promotion authority is a
constant OFF result rather than mutable process state. These are source-private
lifecycle changes only: public/installed ABI, wire values, durable keys and
durable encodings remain byte-exact unchanged.

Host storage profileはESPの69632-byte ceilingを流用しない。改訂OPENの1 active groupは
active row 35247 + NRC1 row 15056 = **50303** logical bytes、1 retained terminal groupは
NM30 row 216 + NRC1 row 15056 = **15272** logical bytesである。

| Host durable bound | exact value / derivation |
| --- | ---: |
| four maximum active committed | `4 * 50303 = 201212` bytes / 8 keys |
| tracked transfer groups | 16 max（32 keys、各groupはactive-or-NM30 + NRC1） |
| committed logical bytes hard max | `4 * 50303 + 12 * 15272 = 384476` |
| one serialized FULL staging max | `50303` bytes / 2 keys |
| begin + final union hard max | `384476 + 50303 = 434779` bytes / 34 row images |
| terminal FULL staging | active erase + NM30 put、NRC1 retained。coordinatorは同時1 terminal FULL |

admissionは新slotのactive+NRC1と将来terminal stagingを含め、上記key/byte/union ceilingを
事前予約できる場合だけ成功する。retention中groupはactive countへ数えないがstore budgetを消費し、
16 tracked groups到達時はGCまでfresh OPENをCAPACITY rejectする。

改訂OPENはactive recordを228 bytes拡大するが、per-slot workspace 65536 bytesとHost owner
aggregate 280064 bytesは変更しない。実装trancheで各slotの未割当slackからexact 228 bytesを
active-record imageへ再配置し、control arena 17920 bytesや他slotのworkspaceを借りない。
本SPEC-only amendmentはproduction allocationやC/C++を変更した根拠にはならない。

Host schedulerはoutbound CHUNK eligible slotだけを対象にする。owner headerの
`next_slot`（初期0）から最大4 slotをcyclic scanし、最初のeligible slot `i`を1件だけ選び、
選択時に`next_slot=(i+1) mod 4`へ進める。同じpeerに未払いCHUNK_OFFERが1件あれば、
そのpeer向け全slotをskipする（他peerは選択可能）。matching CHUNK_ACCEPT、terminal reject、
またはtimeout state transitionまでunpaidを解除しない。継続eligibleかつpeer-blockされない
各slotは最大4回のsuccessful scheduling decision以内に1回選ばれる。restart時は上記canonical
slot再割当後に`next_slot=0`とし、新しいscheduler epochを開始する。wire/storageへslot indexや
cursorを追加せず、本candidateの`0x34..0x43`採番とbody layoutを変更しない。
control outbox trafficはactive scheduler decisionに数えず、`next_slot`やpeer unpaid fenceを
変更しない。active pipeline outboxが未払いのslotはそのdecisionではineligibleとしてskipし、
他のeligible slotを最大4件scanする。control outbox未払いを理由にactive CHUNK fairnessを
停止しない。

### Message type allocation

次の値は`SPEC_ACCEPTED`でreservedとなるcandidateである。全messageはactive sessionの
generation/cookie exact一致、requestはnon-zero request ID、responseはrequest IDをechoし、
NCG1 `DATA`だけに載せる。NFL1/NWB1/NRW1へcontrol messageを載せない。

| message | type | direction / correlation |
| --- | ---: | --- |
| `TRANSFER_OPEN` | `0x36` | sender → receiver request |
| `TRANSFER_OPEN_ACCEPT` | `0x37` | receiver → sender response |
| `MANIFEST_PAGE` | `0x38` | sender → receiver request |
| `MANIFEST_PAGE_ACCEPT` | `0x39` | receiver → sender response |
| `TRANSFER_REJECT` | `0x3a` | receiver/peer → requester response |
| `TRANSFER_BUSY` | `0x3b` | receiver → requester response |
| `CHUNK_OFFER` | `0x3c` | sender → receiver request |
| `CHUNK_ACCEPT` | `0x3d` | receiver → sender response |
| `RESUME_QUERY` | `0x3e` | sender → receiver request |
| `RESUME_STATE` | `0x3f` | receiver → sender response |
| `TRANSFER_FINALIZE` | `0x40` | sender → receiver request |
| `TRANSFER_ACCEPT` | `0x41` | receiver → sender response/final evidence |
| `TRANSFER_ABORT` | `0x42` | current responsibility owner → peer request |
| `TRANSFER_ABORT_ACK` | `0x43` | peer → owner response |

0x34..0x43のunknown/reserved body、wrong direction/type binding、MFN1未成立は業務解釈せず
rejectする。`TRANSFER_REJECT/BUSY`は対応request typeをbody stageでbindする。
各requestは次のexact 1 responseだけで完了する。

| request | success response | alternative response |
| --- | --- | --- |
| OPEN | OPEN_ACCEPT | REJECT / BUSY |
| each MANIFEST_PAGE | MANIFEST_PAGE_ACCEPT | REJECT / BUSY |
| each CHUNK_OFFER | CHUNK_ACCEPT | REJECT / BUSY |
| RESUME_QUERY | RESUME_STATE | REJECT / BUSY |
| TRANSFER_FINALIZE | TRANSFER_ACCEPT | REJECT / BUSY |
| TRANSFER_ABORT | TRANSFER_ABORT_ACK | REJECT / BUSY |

#### Retry budget state machine — `retry_budget_remaining` (active header offset 105)

Closed field on **each** active record (`NM3S` and `NM3R` header byte 105): unsigned
range **0..8**. This is the **only** normative timeout new-ID budget for MFDT v1.
Obsolete phrases such as “7 timeout retries under 64 slots” are **void**.

| property | normative rule |
| --- | --- |
| **scope** | **Per-transfer, per-owner-side** (one counter on that side’s active record). **Not** per-request-id, **not** per-stage, **not** shared across transfers. |
| **owner** | The **requestor** of outbound MFDT control requests on that side. Sender (`NM3S`) owns its outbound OPEN/PAGE/CHUNK/RESUME/FINALIZE/ABORT first attempts and their timeout new-ID retries. Receiver (`NM3R`) owns any receiver-originated outbound requests (e.g. peer-initiated ABORT) the same way. Responder hit-path retransmits do **not** use this budget. |
| **initial value** | **8** (`RETRY_BUDGET_MAX`). Written in the same durable FULL that first creates/binds the active record at OPEN acceptance (both sides independently set 8). |
| **range** | `0..8` inclusive. Values &gt;8 are layout/CORRUPT. |
| **decrement event** | Exactly when the owner-side issues a control request with a **new** non-zero `request_id` that is a **timeout-retry** of a prior same-side request that (1) used a **different** request_id, (2) timed out without durable satisfaction, and (3) shares the same semantic stage unit (same message type + stage binding fields, e.g. same `chunk_index`). Decrement is committed in a durable FULL **before** wire of that new-ID request (`retry_budget_remaining := remaining - 1`). |
| **does not decrement** | First attempt of any semantic unit; same-`request_id` retransmit; response messages; hit-path responder retransmits; new first attempts of unfinished stages after a prior unit completed. |
| **exhaustion** (`remaining == 0`) | **Forbidden:** open any further **new** request_id for timeout-retry. **Allowed:** same-`request_id` retransmit; first attempts of remaining unfinished semantic units; first attempt of a new ABORT generation (charged to `abort_generation` budget, not retry budget). Exhaustion alone is **not** terminal, **not** NRC1 eviction, and **not** automatic ABORT. If progress is impossible without a new-ID timeout retry, peer must ABORT (if permitted) or wait; it **must not** invent new request IDs. |
| **terminal erase** | G_*_TERMINAL erases the active record (budget dies with it). |

Machine constants (closed):

```text
RETRY_BUDGET_MAX     = 8   # initial and maximum
RESUME_QUERY_MAX     = 8
ABORT_GEN_MAX        = 8
MAX_PAGES            = 2
MAX_CHUNKS           = 37
```

#### Terminal outcome exclusivity (budget SM edge)

Successful terminal outcomes are **mutually exclusive** on one transfer:

- **COMPLETE path**: successful `TRANSFER_FINALIZE` → `TRANSFER_ACCEPT` → NM30 COMPLETE.
  Successful ABORT terminal is forbidden after content-verified; ABORT requests in that region
  are **ABORT_DENIED** (REJECT) but still produce a first durable response (NRC1 slot).
- **ABORT path**: successful ABORT → NM30 ABORTED before content-verified.
  Successful FINALIZE is not admitted on this path (no FINALIZE first-attempt in the bound).

CORRUPT_FENCED is a third terminal class and does not add OPEN/PAGE/CHUNK first-attempt budget
beyond the max-size ABORT/COMPLETE envelopes above.

#### Request-ID response cache — durable `NRC1` (closes RAM-only contradiction)

**Choice (a):** the response cache is a **durable** MFDT sidecar namespace kind, not process RAM.
A first response after FULL cannot be “forgotten” across restart and then re-evaluated into a
second body for the same request ID.

##### Durable key / value

| field | rule |
| --- | --- |
| kind magic | `NRC1` |
| key | 20 bytes exact: `NRC1[4] \|\| transfer_id[16]` (one cache row per transfer per owner) |
| owner | the **responder** of that request (typically receiver for OPEN/PAGE/CHUNK/RESUME/FINALIZE; peer for ABORT_ACK) |
| schema | 1 |
| capacity | **72** fixed slots; **no silent eviction** of non-empty slots while non-terminal

**Session-generation binding (P0 close):** each NRC1 slot binds `session_generation`.
RESUME first-attempts are **per session generation** (`RESUME_QUERY_MAX=8`). Reconnect is a
fresh session generation. Advancing session generation is a durable FULL that **reclaims
RESUME-class slots** of prior generations before admitting new RESUME first-attempts.
Non-RESUME slots are retained whole lifetime (including post-terminal until GC).
Peak occupancy = NON_RESUME(57) + RESUME_PER_GEN(8) = **65 ≤ 72**. Without reclaim,
2 gens would need 73 slots (**illegal**; CAPACITY).
`SESSION_GEN_MAX_PER_TRANSFER=2` is the maximum number of **distinct consecutive
generation values in one transfer lifetime**; it is not an upper bound on the numeric
value of `session_generation`.

The initial generation is any caller-bound **non-zero `u32`**. When an NRC1 contains a
prior generation, the earliest retained non-RESUME `OPEN_ACCEPT` slot is the
transfer-generation anchor. The NRC1 header must then equal exact `anchor + 1`;
occupied slots may bind only the header generation or its exact predecessor. Thus initial `7`, and then
`7 -> 8`, are valid while `0`, rollback, a gap, a future slot, a third distinct
generation, and wrap are CORRUPT. An empty NRC1 has no durable generation anchor and is
not eligible for generation advance.

Advance is exact `current + 1`, requires `current != UINT32_MAX`, and is allowed only
when the NRC1 has no already-retained prior generation. The advance FULL reclaims only
current-generation `RESUME_STATE` slots. Every non-RESUME slot remains byte-exact, and
after the FULL becomes the prior-generation evidence. A second advance would create a
third transfer generation and is therefore rejected as CAPACITY.

**Capacity — generated from the retry-budget SM (not hand-waved 57+7):**

Late-duplicates require bit-exact retention of every first response. Each distinct request_id
that receives a first response occupies one NRC1 slot for the whole transfer lifetime until retention GC (not terminal erase). First-attempt
counts and timeout new-ID counts are **outputs of the SM above**.

```text
# First-attempt semantic units (not charged to retry_budget_remaining)
FIRST_OPEN     = 1
FIRST_PAGES    = MAX_PAGES            # 2
FIRST_CHUNKS   = MAX_CHUNKS           # 37
FIRST_RESUME   = RESUME_QUERY_MAX     # 8
FIRST_FINALIZE = 1                    # COMPLETE path only
FIRST_ABORT    = ABORT_GEN_MAX        # 8 first attempts (success or ABORT_DENIED)
RETRY_NEW_IDS  = RETRY_BUDGET_MAX     # 8 = sum of all timeout new-ID decrements

# COMPLETE path (successful FINALIZE terminal; exclusive of successful ABORT)
# Includes ABORT_DENIED first-attempts after content-verified (each caches REJECT).
N_complete =
  FIRST_OPEN + FIRST_PAGES + FIRST_CHUNKS + FIRST_RESUME
  + FIRST_FINALIZE + FIRST_ABORT + RETRY_NEW_IDS
  = 1 + 2 + 37 + 8 + 1 + 8 + 8
  = 65

# ABORT-success path (before content-verified; no successful FINALIZE first-attempt)
N_abort =
  FIRST_OPEN + FIRST_PAGES + FIRST_CHUNKS + FIRST_RESUME
  + FIRST_ABORT + RETRY_NEW_IDS
  = 1 + 2 + 37 + 8 + 8 + 8
  = 64

NRC1_REACHABLE_MAX_IDS = max(N_complete, N_abort) = 65
NRC1_HAPPY_FIRST       = FIRST_OPEN + FIRST_PAGES + FIRST_CHUNKS + FIRST_FINALIZE = 41
```

Naive union `1+2+37+8+1+8 = 57` (FINALIZE success **and** ABORT success together) is **not** a
reachable single-path bound and is rejected as authority.

Implemented `slot_count = 72 ≥ 65` (spare `72 − 65 = 7`). Admitted policy that stays within
SM budgets **must** reach its terminal FULL without `request_id_cache_full` solely due to
slot starvation. Peers **must not** open more than **72** distinct request IDs on one
transfer; further misses ⇒ CAPACITY. Fixed-16 and “64 slots with 7 timeout retries” are void.

**Value layout** (exact **15020** bytes, big-endian, reserved=0):

```text
offset  bytes  field
0       4      magic = "NRC1"
4       2      schema = 1
6       2      value_length = 15020
8       16     transfer_id (must equal key transfer_id)
24      4      current_session_generation (active header offset 300と一致、non-zero)
28      2      slot_count = 72
30      2      occupied_count (0..72)
32      4      next_insert_seq (monotonic u32, wraps only after terminal erase)
36      4      header_crc32c over bytes [0,36)
40      208*72 slots[0..71]
15016   4      record_crc32c over all preceding value bytes
```

**Slot layout** (208 bytes each):

```text
0       8      request_id; 0 = empty slot
8       4      session_generation; occupied時non-zero、requestを受けたgeneration exact
12      32     request_body_digest (exact preimage below)
44      2      response_message_type (e.g. 0x37 OPEN_ACCEPT, 0x39 PAGE_ACCEPT, …)
46      2      response_body_length L (occupied時1..160)
48      160    response_body[0..L) left-justified; trailing bytes zero
```

**Exact `request_body_digest` preimage** (all request types, including OPEN without BIND52):

```text
request_body_digest = SHA-256(
  message_type_u8 ||
  body_length_u16_be ||
  body[0 .. body_length)
)
```

- `message_type` / `body` / `body_length` are the MFDT control message type and body after
  NCL1/session framing is stripped (not including NCL1 header).
- `body` is the **full** MFDT body. For `TRANSFER_OPEN` that is the entire OPEN body
  (starts at `transfer_id[16]`; **no** BIND52 strip — OPEN has no BIND52 prefix).
- For BIND52-bearing messages (`MANIFEST_PAGE`, `CHUNK_OFFER`, …) `body` **includes**
  the leading BIND52 (there is **no** “digest after BIND52” rule; that wording is void).
- Empty body is forbidden for cacheable requests.

Empty slots: request_id=0 and all other fields（session generationとLを含む）zero。
Non-empty: request_id≠0、session generation≠0、L in 1..160、response body
left-justified、trailing zeros、type ∈ closed MFDT response set。lookup identityは
**`(session_generation, request_id)` exact pair**であり、異generationの同じrequest IDを
同一slotとして扱わない。

##### Pre-admission OPEN refusal（NRC1の明示的な範囲外）

NRC1のlifetimeとbit-exact first-response規則は、`G_R_OPEN` FULLが成功して
responderがtransfer responsibilityを受けた時点から、retention GCまでに届く
**cacheable request**へ適用する。durable activeまたはretained terminal groupへ
bit-exact bindできるrequestはcacheableであり、下記のhit/miss規則を省略できない。

一方、fresh `TRANSFER_OPEN`を評価したが`G_R_OPEN`を一度も開始・成功していない
pre-admission refusalは、まだtransfer lifetimeを作っていないためNRC1の明示的な
範囲外である。policy OFF、期限、capacity、またはOPEN layout/digest不適合による
このrefusalは次をすべて満たす。

- active/NM30/NRC1を作らず、FULL count 0、durable state mutation 0。
- OPEN bodyが少なくとも234 bytesあり、`transfer_id`、`manifest_revision`、
  `manifest_digest`がすべてnon-zeroで安全にBIND52を構成できる場合だけ、
  exact `REJECT`または`BUSY`を返す。response bodyは
  `BIND52 || stage=OPEN(1) || reject_code_u16 || detail_u32`の60 bytes exact。
- 上記bindを構成できないshort/zero/malformed inputはwire response 0とし、
  semantic/layout errorだけをcallerへ返す。unbound REJECTを合成しない。
- Host transport APIはexact response frameをowned outboxへ保持できた場合
  `OK`を返し、application-level refusalはresponse bodyで表す。outboxを所有できない
  場合は`OK`へ変換しない。bearerがframeをtakeするまでownerはframeを保持する。
- stateless refusalはrequest IDをdurableに予約しない。同じpacketのlate duplicateは
  現在のadmission stateで再評価され得るためbit-exact replayを要求しない。
  refusalを受信したrequestorが再試行する場合はfresh non-zero request IDを使う。
  admission成功後に同じtransferへ届くrequestは、この例外ではなく通常のNRC1規則へ従う。
- NRC1だけが存在しactive/NM30のどちらも存在しないorphan groupを作ることは禁止する。

Hostの4 active slotがすべて埋まっていても、5件目のfresh OPENに対する上記
CAPACITY/BUSYを既存slotへ混入させてはならない。Host profileはactive slotとは独立した
bounded control outboxを1件分持ち、そのframeが未払いの間は次のstateless responseを
`BUSY`でbackpressureする。既存4 transfer、scheduler cursor、storeは変更しない。

##### On request (deterministic)

1. Load NRC1 for this transfer (absent ⇒ treat as empty row, occupied=0).
2. **Hit**: active sessionと一致する`session_generation + request_id` pairを持つslotを探す。
   - digest match ⇒ retransmit **bit-exact** `response_body[0..L)` (no state mutation, no FULL).
   - digest mismatch ⇒ REJECT code 3 (`request_id_body_digest_conflict`), mutation 0.
3. **Miss**:
   - if `occupied_count == 72` ⇒ REJECT/BUSY code 5 CAPACITY (`request_id_cache_full`), mutation 0
     (**no eviction** of live slots).
   - else evaluate against **current durable NM3\*** state, form one response, then in the
     **same FULL** as any durable effect of that evaluation (or a dedicated
     `G_*_REQID_CACHE` FULL if the response has no other durable effect), write/replace
     the NRC1 row with the new slot filled **before** wire send. Wire send is allowed only
     after that FULL succeeds (or after hit path).
4. **Timeout retry**: same semantic body **must** use a **new** non-zero request ID and
   **must** follow the retry-budget SM (decrement `retry_budget_remaining` before wire;
   refuse new-ID retry when remaining is 0). New ID ⇒ miss path ⇒ response may reflect
   current durable state (complete 0→1 OK). Distinct IDs still consume NRC1 slots until
   terminal; peers must stay within 72.
5. **Retention (closes terminal late-duplicate contradiction):** NRC1 is **not** erased at
   terminal. Bit-exact first-response stability for late duplicates applies for the **entire**
   transfer lifetime **including post-terminal**, until retention GC. NM30 schema 2 is only 180 bytes and
   **cannot** regenerate PAGE_ACCEPT / CHUNK_ACCEPT / OPEN_ACCEPT / RESUME_STATE /
   TRANSFER_ACCEPT / ABORT_* bodies; therefore NRC1 must outlive active erase.
   - **Active phase:** NRC1 + NM3S/NM3R present.
   - **`G_*_TERMINAL` FULL:** erase **active only** + put NM30; **NRC1 remains** (same
     final view does **not** delete NRC1).
   - **Retention window:** keys present = NM30 + NRC1 (no active). Late-duplicate hit path
     is still bit-exact from NRC1. New first-attempt misses cannot mutate terminal transfer
     state and produce REJECT (`request_id_post_terminal_new_miss`, code STATE);
     the exact first response is nevertheless inserted by one dedicated NRC1-only FULL
     before wire（transfer-state mutation 0、cache FULL count 1）。
   - **Retention GC FULL** (`G_*_RETENTION_GC`): delete NM30 **and** NRC1 together after
     retention elapses (or explicit upper handoff policy). After GC, both keys absent ⇒
     closed response `transfer_expired` / REJECT code EXPIRED (not a bit-exact body replay).
   - Session reset / epoch CORRUPT_FENCED terminal: same as COMPLETE/ABORT for NRC1 retention
     (NRC1 kept until GC with the NM30 tombstone).
6. **Forbidden**: two different success bodies for one request_id; RAM-only cache; returning
   current complete=1 for a request_id whose durable slot still holds complete=0;
   silent eviction; capacity below `NRC1_REACHABLE_MAX_IDS` (65); erasing NRC1 at terminal
   while still promising whole-lifetime bit-exact replay; inventing post-terminal bodies from
   NM30 alone.

Session generation advanceはactive NM3S/NM3Rのoffset 300とNRC1 header offset 24を
同じFULLでexact `old + 1`へ更新し、NRC1では**prior-generation RESUME response slotだけ**を
zeroへ戻す。non-RESUME slotは元のper-slot generationを保持する。同じFULLでactive
`last_resume_query_generation`を0へresetし、NRC1 `occupied_count`と`next_insert_seq`を
残存slotからcanonical再計算する。`SESSION_GEN_MAX_PER_TRANSFER=2`は数値上限ではなく、
初期の任意non-zero `u32`と、そのexact successorというdistinct generation数の上限である。
prior generationを持つNRC1では初期non-RESUME `OPEN_ACCEPT` slotをanchorとし、
currentまたはexact priorだけを認める。既にprior-generation slotが存在する状態での
再advance、`UINT32_MAX + 1`、
generation rollback、gap、future、active/NRC1不一致、異generation slotを現在generation
hitとして返すことはCORRUPT fenceまたはadvance CAPACITYであり、wire replay 0。

##### FULL ordering / budget (includes dedicated REQID FULLs)

- First response for a request_id that **also** mutates NM3\* state: NRC1 slot insert is
  **co-located** in that group FULL (`G_R_OPEN` / `G_R_PAGE` / `G_R_CHUNK` / `G_R_RESUME` /
  `G_R_CONTENT` / `G_R_ACCEPT` / …). No extra FULL beyond the group count.
- First response with **no** other durable mutation (NRC1-only): one dedicated FULL
  `G_R_REQID_CACHE` / `G_S_REQID_CACHE` (count 1) **before** wire. This includes:
  - content-verified **ABORT_DENIED** first responses (up to `ABORT_GEN_MAX=8`);
  - timeout **new-ID** first responses that only insert an NRC1 slot (up to
    `RETRY_BUDGET_MAX=8`).
- Each **RESUME_QUERY** first-attempt that updates `last_resume_query_generation` is a
  durable mutation FULL `G_R_RESUME` / `G_S_RESUME` (count 1 per first-attempt, max
  `RESUME_QUERY_MAX=8`), co-located with its NRC1 slot insert.
- Hit retransmit: 0 FULL.
- **Exact max-size COMPLETE path FULL counts (machine-pinned):**

```text
# Receiver (responder for OPEN/PAGE/CHUNK/RESUME/FINALIZE/ABORT_DENIED)
G_R_OPEN + G_R_PAGE + G_R_CHUNK + G_R_CONTENT + G_R_ACCEPT + G_R_HANDOFF + G_R_TERMINAL
  = 1+2+37+1+1+1+1 = 44          # co-located progression (NRC1 not erased at terminal)
G_R_RESUME                         = RESUME_QUERY_MAX = 8
G_R_REQID_CACHE                    = ABORT_DENIED_MAX + RETRY_BUDGET_MAX = 8+8 = 16
receiver_fulls_max_transfer        = 44 + 8 + 16 + 8 + 1 = 77  # +RETRY_BUDGET FULL 8 + SESSION_GEN 1

# Sender
G_S_OPEN + G_S_OPEN_RX + G_S_MANIFEST + G_S_CHUNK + G_S_ACCEPT + G_S_TERMINAL
  = 1+1+1+37+1+1 = 42
G_S_RESUME                         = 8   # when sender issues RESUME_QUERY first-attempts
G_S_REQID_CACHE                    = 8   # sender-as-responder non-mutation first bodies
                                       # (e.g. ABORT_ACK path / timeout new-ID as responder)
sender_fulls_max_transfer          = 42 + 8 + 8 + 8 + 1 = 67  # +RETRY_BUDGET FULL 8 + SESSION_GEN 1
```

- Obsolete claim “receiver 44 / sender 42 covers max-ID path including RESUME/ABORT_DENIED/
  timeout REQID-only FULLs” is **void**. Daily wear for 2 max-size transfers as receiver:
  `77 * 2 = 154` receiver / `67 * 2 = 134` sender (not 88/116).
- Admission while active: reserve active + NRC1 (+ NM30 staging at terminal) as before.
  After terminal until GC: reserve **NM30 + NRC1** (2 keys / 216+15056 = 15272). ESP pin:
  at most one active transfer; at most one retained (NM30+NRC1) tombstone set concurrent with
  a new active is allowed only if namespace final view stays ≤32 keys / 69632 bytes.

##### Restart / COMMIT_UNKNOWN / post-terminal late duplicate

- Restart loads NRC1 whenever present (active **or** post-terminal retention). A hit is
  bit-exact without semantic re-evaluation **only for the Host FULL-capable profile**。
  target promotion-ONは本profileでUNALLOCATEDなので、targetはOFF ruleから外れない。
- After terminal, before GC: same hit/miss algorithm on NRC1; digest conflict still REJECT 3.
- After retention GC (NRC1 and NM30 absent): no bit-exact body; closed REJECT
  `transfer_expired` (EXPIRED), mutation 0.
- NRC1 COMMIT_UNKNOWN: OLD/NEW/ABSENT/PARTIAL/THIRD as usual; ABSENT after prior success
  while NM30 still present (or mid-active) is CORRUPT fence (cache loss without GC).
- Crash after durable effect FULL before NRC1 slot write: dual-key group fault if co-located;
  co-location forbids that split.

**Unattested ESP replay boundary (candidate amendment, 2026-07-30):**

| local storage profile | first `COMMIT_UNKNOWN` readback `NEW` | same-ID retry in same process | cold restart with active+NRC1 | cold restart with retained NM30+NRC1 |
| --- | --- | --- | --- | --- |
| Host FULL-capable | not an ESP-unattested event; `STORAGE_OK` is usable | bit-exact NRC1 replay | bit-exact NRC1 replay | bit-exact NRC1 replay |
| ESP target, physical-HIL promotion OFF | adopt bytes only as recovery state; wire success/accept **0** | `COMMIT_UNKNOWN`; no NRC1 body | `COMMIT_UNKNOWN`; no NRC1 body | `COMMIT_UNKNOWN`; no NRC1 body |
| ESP target, promotion ON | **UNALLOCATED / UNSUPPORTED** | no replay permission | no replay permission | no replay permission |

The ESP OFF rule is deliberately profile-wide: NRC1 schema 1 has no per-slot
attestation/provenance field, so after a cold restart it is impossible to distinguish a slot
written by an unattested `COMMIT_UNKNOWN`/NEW from one eligible for external replay. The
implementation therefore must not infer eligibility from NRC1 presence, CRC, active/NM30
presence, or readback equality. This applies both to mutation+NRC1 FULL groups and NRC1-only
FULL groups. Promotion ONのevidence schema、trust anchor、anti-rollback、expiry/revocation、
replay ruleは本profileでは採番しない。将来のProposed amendmentがS1–S6と独立reviewを
通すまでONへ遷移するAPI/設定は常にUNSUPPORTEDを返す。MF-O08はtarget/HIL/release blocker
としてOPENのままであるが、promotion-OFFだけを対象とするdesign SPEC acceptanceとは分離する。
これはAccepted U6を変更せず、HIL evidenceをfabricateしない。

Vectors: `MF-POS-REQID-CACHE-SAME-ID-STABLE`, `MF-POS-REQID-NEW-ID-CURRENT-COMPLETE`,
`MF-POS-REQID-NRC1-LAYOUT-KAT`, `MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41`,
`MF-POS-REQID-RETRY-BUDGET-SM`, `MF-POS-REQID-REACHABLE-MAX-COUNT`,
`MF-POS-REQID-MAX-RETRY-TRACE`, `MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX`,
`MF-TX-REQID-TERMINAL-RESTART-LATE-DUP`, `MF-NEG-REQID-POST-RETENTION-EXPIRED`,
`MF-BUDGET-FULL-MAX-WITH-REQID`, `MF-TX-REQID-CACHE-CRASH-RESTART`,
`MF-NEG-REQID-BODY-CONFLICT`, `MF-NEG-REQID-CACHE-FULL`,
`MF-NEG-REQID-DIGEST-OPEN-PREIMAGE`, `MF-CU-NRC1-ABSENT-MID-TRANSFER`,
`MF-BUDGET-NRC1-LOGICAL-BYTES`.

### Canonical manifest

全multi-byte integerはunsigned big-endian、全reserved/flagsは0である。namespaceは
`[a-z0-9][a-z0-9.-]*`、service/schemaは`[a-z0-9][a-z0-9._-]*`のASCIIで各1..63 bytesとし、
Foundation `ninlil_text_id_t`へbit-exact projectする。UTF-8一般やNULを許可しない。IDは16-byte all-zero禁止、
digest algorithmはSHA-256 exact `0x0001`、digestはall-zero禁止である
（empty contentのwhole digest `SHA-256("")`は非zeroなので許可）。

`TRANSFER_OPEN` bodyはbaselineの先頭234 bytesをbyte-exactに保ち、その後に
fixed 228-byte Application binding、さらに3 text fieldsを置く。fixed totalは462 bytes、
minimumは465 bytes、maximumは**651 bytes**である。これはNCL1 body max 998未満である。

```text
offset  bytes  field
0       16     transfer_id
16      4      manifest_revision, >=1
20      4      total_length, 0..32768
24      2      chunk_size, exact 896
26      2      chunk_count, derived 0..37
28      2      manifest_page_count, derived 0..2
30      2      entries_per_page, exact 22
32      32     whole_content_sha256
64      16     origin_transaction_id
80      16     origin_event_id; zero only when family permits
96      16     source_runtime_id
112     16     target_runtime_id
128     8      service_descriptor_revision, >=1
136     2      service_descriptor_digest_algorithm = 1
138     32     service_descriptor_digest
170     2      namespace_length, 1..63
172     2      service_length, 1..63
174     2      schema_length, 1..63
176     2      flags = 0
178     16     deadline_clock_epoch_id
194     8      absolute_effect_deadline_ms
202     32     manifest_digest
234     16     original_attempt_id
250     4      target_ordinal_u32
254     16     source_application_instance_id
270     16     source_device_id
286     16     source_installation_id
302     16     source_site_domain_id
318     8      source_binding_epoch_u64
326     8      source_membership_epoch_u64
334     4      source_identity_flags_u32
338     4      source_reserved_u32 = 0
342     16     target_application_instance_id
358     16     target_device_id
374     16     target_installation_id
390     16     target_site_domain_id
406     8      target_binding_epoch_u64
414     8      target_membership_epoch_u64
422     4      target_identity_flags_u32
426     4      target_reserved_u32 = 0
430     2      service_schema_major_u16
432     2      service_schema_minor_u16
434     4      service_family_u32
438     8      application_generation_u64
446     8      evidence_grace_ms_u64
454     4      required_evidence_u32
458     4      application_binding_flags_u32 = 0
462     N      namespace || service || schema
```

uplink `EventFact`の`NO_DEADLINE`はFoundation canonicalどおり、deadline epochがall-zero、
`absolute_effect_deadline_ms = NINLIL_NO_DEADLINE (UINT64_MAX)`、
`evidence_grace_ms = 0`である。finite downlink `DesiredState`はdeadline epochがnon-zero、
`absolute_effect_deadline_ms`が`1..UINT64_MAX-1`である。deadline `0`、downlinkの
`UINT64_MAX`、またはこれらとepoch/family/generation/evidence shapeが一致しない組合せは
canonicalでなくrejectする。senderはoriginal ordinary Application envelopeのdeadline bytesを
OPENへbit-exactに転記し、`0`、`UINT64_MAX`、その他の値へ正規化してはならない。
source/target identity flagsはFoundationの同名presence ruleに従い、present bitとIDの
non-zeroが一致する。application identity、epoch、Service schema/family、generation、
evidenceはordinary Application envelopeとしてvalidでなければならない。

manifest digestのexact preimageは次である。Application bindingの228 bytes全体を含め、
manifest digest field自身だけを除く。

```text
manifest_digest =
  SHA-256(ASCII("NM3-MANIFEST-V1") ||
          open[0,202) ||
          open[234,462) ||
          open[462,open_body_length) ||
          manifest_entry[0] || ... || manifest_entry[chunk_count-1])
```

ASCII domainは終端NULを含めない。digest field自身、request/session fields、page header/page digestは
inputに含めない。同じtransfer IDでrevision/digest/open bytesの1 byteでも違えば
`DUPLICATE_CONFLICT`であり、higher revisionによるin-place置換はしない。新しい内容は新transfer IDを
要する。

#### Original Application / private carrier / OPEN validation（pre-FULL）

senderは`G_S_OPEN`を開始する前に、senderが受理したoriginal ordinary Application envelopeと
生成済みOPENのorigin transaction/attempt/event、source/target Runtime、Application instance、
identity/epochs/flags、Service text/revision/digest/schema/family、content digest/length、generation、
deadline/evidence、target ordinalをbit-exactに比較する。これはoriginal Application全fieldを
OPENへ転記する境界であり、1 fieldでも不一致ならOPENを送らず、`G_S_OPEN` FULL、durable row、
callback、Receiptを0とする。senderはorigin transactionのexact full rosterを保持するため、
target ordinalが該当bound-targetのcanonical array indexと一致することもここで検査する。

receiverは`G_R_OPEN`を開始する前に、authenticated private MFDT carrierとOPENのうち、
source/target Runtime ID、Application instance ID、identity IDs、binding/membership epochs、
identity flagsだけをbit-exactに比較する。private carrier自身のtransaction ID、attempt ID、
private MFDT Service、NCL1 payload digestはcontrol envelopeのfieldであってoriginal Application
envelopeのfieldではないため、OPENのorigin transaction/attempt、ordinary Service、content digest
とは比較しない。

receiverはOPEN内の残りのoriginal Application fieldをordinary Application envelopeとしてcanonical
validation/authorizationする。receiverはorigin senderのfull rosterを再構成せず、target ordinalが
`0 <= ordinal < Foundation exact-target maximum (4)`であること、OPEN target identityが
authenticated local target identityと一致することだけを検査する。さらにtransfer IDをOPEN内の
origin transaction、target Runtime、target ordinalから再導出してexact一致を要求する。その導出は
`SHA-256(origin_transaction_id[16] || target_runtime_id[16] || target_ordinal_u32_be ||
ASCII("ninlil-mfdt-v1id"))[0..15]`で、ASCIIにNULは含めない。結果がall-zeroの場合は
byte 15を1とする。admission profile revision 2でもこのtransfer-ID導出は変更しない。
receiver-side party/target subsetの不一致、OPEN canonical validation/authorization失敗、target ordinal bound/
transfer-ID再導出の不一致、またはcarrierのMFN1 admission revisionとOPEN layout revisionの不一致は
REJECT code 4/9、`G_R_OPEN` FULL 0、durable row 0、state mutation 0とする。一部一致やvolatile
bindingを根拠に不足fieldを補完しない。

各manifest entryは40 bytes exact:

```text
chunk_index_u16 | chunk_length_u16 | chunk_offset_u32 |
chunk_sha256[32]
```

indexは0から連続、offset/lengthは上の導出値と一致し、digestはall-zero禁止である。
`MANIFEST_PAGE` bodyは92 + 40 * entry_count bytes、entry countは1..22で最大972 bytes:

```text
0/16 transfer_id
16/4 manifest_revision
20/32 manifest_digest
52/2 page_index
54/2 page_count
56/2 first_chunk_index
58/2 entry_count
60/32 page_digest
92/... canonical manifest entries
```

page indexは0から連続、page countはOPENと一致、first indexは`22 * page_index`、
non-final page entry countは22、finalは残数exactとする。
`page_digest = SHA-256("NM3-PAGE-V1" || transfer_id || manifest_revision_u32_be ||
manifest_digest || page_index_u16_be || page_count_u16_be || first_chunk_index_u16_be ||
entry_count_u16_be || entry bytes)`である。pageを全部FULL保持して全entryをcanonical順に再構成し、
manifest digestが一致した後だけ最後のMANIFEST_PAGE_ACCEPTで`manifest_complete=1`を送る。
Private encoderはcallerのexact final `page_out`（最大972 bytes）をdigest preimage
scratchとして再利用し、process-global mutable scratchを持たない。`entries`はoutとdisjoint、
またはexact `page_out + 92`だけを許し、他の入力/output overlapと全semantic invalid inputは
output mutation前にrejectする。

### Other body layouts

以下の`BIND52`は
`transfer_id[16] || manifest_revision_u32_be || manifest_digest[32]`である。

| Message | exact body |
| --- | --- |
| `TRANSFER_OPEN_ACCEPT` | `BIND52 || reservation_id[16] || reserved_total_length_u32 || reservation_clock_epoch_id[16] || reservation_not_after_ms_u64 || manifest_complete_u8 || reserved[3]=0` = 100 bytes |
| `MANIFEST_PAGE_ACCEPT` | `BIND52 || page_index_u16 || received_page_count_u16 || page_digest[32] || reservation_id[16] || manifest_complete_u8 || reserved[3]=0` = 108 bytes |
| `TRANSFER_REJECT` | `BIND52 || rejected_stage_u16 || reject_code_u16 || detail_u32` = 60 bytes |
| `TRANSFER_BUSY` | `BIND52 || busy_stage_u16 || reserved_u16=0 || retry_after_ms_u32` = 60 bytes |
| `CHUNK_ACCEPT` | `BIND52 || chunk_index_u16 || reserved_u16=0 || chunk_sha256[32]` = 88 bytes |
| `RESUME_QUERY` | `BIND52 || query_generation_u32 || reserved_u32=0` = 60 bytes |
| `TRANSFER_FINALIZE` | `BIND52 || whole_content_sha256[32] || total_length_u32 || reserved_u32=0` = 92 bytes |
| `TRANSFER_ACCEPT` | `BIND52 || whole_content_sha256[32] || total_length_u32 || receiver_evidence_id[16] || acceptance_record_generation_u64 || reservation_id[16] || acceptance_record_digest[32]` = 160 bytes |
| `TRANSFER_ABORT` | `BIND52 || abort_reason_u16 || reserved_u16=0 || authority_actor_id[16] || abort_generation_u32` = 76 bytes |
| `TRANSFER_ABORT_ACK` | `BIND52 || abort_generation_u32 || final_state_u16 || reserved_u16=0 || tombstone_digest[32]` = 92 bytes |

`TRANSFER_OPEN_ACCEPT.reserved_total_length`はOPEN total lengthとexact一致する。
reservation ID/clock epochはnon-zeroである。receiverはtrusted local platform monotonic sampleの
epochをreservation epochとする。reservation boundは次のchecked algorithmだけで決める。

1. `now_ms > UINT64_MAX - 300000`ならREJECT code 7
   (`reservation_deadline_overflow`)、state mutation 0。
2. `base_not_after = now_ms + 300000`。
3. OPENがNO_DEADLINEなら`reservation_not_after_ms = base_not_after`。
4. OPEN deadline epochがlocal epochと一致する場合、`deadline_ms <= now_ms`なら
   REJECT code 7 (`effect_deadline_expired`)、state mutation 0。それ以外は
   `reservation_not_after_ms = min(base_not_after, deadline_ms)`。
5. OPEN deadline epochが異なる場合、Accepted deadline-projection recordがlocal epochへ
   bit-exact変換済みでなければREJECT code 8 (`deadline_projection_unavailable`)、
   state mutation 0。projection resultが`<= now_ms`ならcode 7、それ以外は上と同じmin。

異epoch値を直接数値比較しない。成功時のnot-afterはnon-zeroかつ`> now_ms`で、OPEN_ACCEPTと
active recordへ同一FULLで固定し、retry/restartで延長しない。
`manifest_complete`はzero-length OPENでexact 1、それ以外はOPEN_ACCEPT時0である。

#### Mid-transfer local clock epoch change (normative terminal path)

If `local_clock_epoch_id` observed by the multi-frame owner **changes** while an active
NM3R/NM3S transfer exists (any non-terminal durable active state):

1. **Immediate fence**: stop accepting further MANIFEST_PAGE / CHUNK_OFFER / FINALIZE
   effects; set publication to NONE if not already HANDOFF-complete; **forbid** new
   `publication_token` READY and any upper `prepare()` after the fence.
2. **Terminal transition** (same FULL group as other terminals): erase active key + put
   NM30 with `terminal_state=CORRUPT_FENCED(3)`, `terminal_reason=0x8002` (`EPOCH_CHANGED`),
   `abort_generation=0`, `authority_actor_id=0`, retention anchors from pre-fence sample.
3. **Reservation reclaim**: reservation_id becomes invalid; `reservation_not_after_ms` is
   not extended and not compared across epochs; peer OPEN reuse of that reservation is
   REJECT code 8 STATE.
4. **Wire status** for subsequent peer messages on the same transfer bind:
   REJECT code 8, reason `local_clock_epoch_changed`, stage of the message; state mutation 0
   beyond the already-committed terminal FULL.
5. **No stale publish**: if publication was READY but handoff not FULL, discard READY and
   never prepare; if handoff already FULL, epoch change after handoff does not revoke the
   application effect (upper contract), but multi-frame owner still completes NM30
   CORRUPT_FENCED for storage hygiene only when handoff not yet terminalized.

Vectors: `MF-NEG-EPOCH-CHANGE-MID-TRANSFER`, `MF-TX-EPOCH-CHANGE-TERMINAL`.

各MANIFEST_PAGEはFULL後に同じpage index/digestを持つPAGE_ACCEPTを1件返す。
`manifest_complete=1`は全page bitmap、entry、page digest、whole manifest digest検証後にだけ
許す。初回は最後の不足page responseで0→1になる（**そのrequest IDの初回**）。
**同一request ID**のlate duplicateはrequest-id cacheの**初回PAGE_ACCEPT bit-exact**を返す
（complete=0のまま保持され得る）。**新しいrequest ID**のretryだけがcurrent
complete=1とcurrent received countを返してよい。2-page時の先行pageへ初回はcomplete=0
responseを返す。zero-pageではOPEN_ACCEPTのcomplete=1が同じ意味を持つ。

`CHUNK_OFFER` bodyは96 + chunk lengthで最大992 bytes:

```text
BIND52 || chunk_index_u16 || chunk_count_u16 ||
chunk_offset_u32 || chunk_length_u16 || reserved_u16=0 ||
chunk_sha256[32] || chunk_bytes
```

index/count/offset/length/digestはaccepted manifest entryとbit-exact一致し、
SHA-256(chunk bytes)も一致する。same index + same bytesはidempotent、
same index + different bytes/digestはtransfer terminal conflictとする。

`RESUME_STATE`は108 bytes:

```text
BIND52 || query_generation_u32 || receiver_record_generation_u64 ||
committed_chunk_bitmap_u64 || transfer_state_u16 || reserved_u16=0 ||
state_digest[32]
```

bitmap bit `i`だけがchunk iのFULL commitを表し、chunk_count以上のbitは0。
`state_digest = SHA-256("NM3-RESUME-V1" || preceding 76 body bytes)`。
senderはbitmapを成功証拠やpayload解放根拠にせず、missing chunkを再OFFERするhintにだけ使う。

全chunkのCHUNK_ACCEPTをsender側FULLした後、zero-lengthを含め必ずTRANSFER_FINALIZEを送る。
receiverはall chunk bitmap、whole digest、content-verified FULLを再検査し、matching
TRANSFER_ACCEPTだけを返す。TRANSFER_ACCEPTのdigestは次でexact計算する。

```text
acceptance_record_digest =
  SHA-256(ASCII("NM3-ACCEPT-V1") ||
          BIND52 ||
          whole_content_sha256[32] ||
          total_length_u32_be ||
          receiver_evidence_id[16] ||
          acceptance_record_generation_u64_be ||
          reservation_id[16])
```

domain ASCIIに終端NULを含めない。acceptance digest field自身、request ID、session、record CRCを
含めない。`acceptance_record_generation`はreceiverがcontent-verified FULLへ遷移するrecord
generationで固定し、後続publication更新で変えない。

`tombstone_digest = SHA-256(complete canonical NM30 value including its stored CRC32C)`とする。
NM30自身にtombstone digest fieldはないため循環しない。ABORT_ACKはFULL readbackしたNM30だけから
再計算し、partial/unknown recordへdigestを返さない。

### Closed status catalogs

Stageは`OPEN=1, MANIFEST=2, CHUNK=3, FINAL=4, RESUME=5, ABORT=6`だけ。
reject codeは次だけを許す。

| code | meaning |
| ---: | --- |
| 1 | layout/length/reserved |
| 2 | digest mismatch |
| 3 | duplicate conflict |
| 4 | unsupported version/profile/carrier mapping |
| 5 | capacity/reservation |
| 6 | storage definite failure |
| 7 | expired/deadline |
| 8 | state/order |
| 9 | authority/identity/service mismatch |
| 10 | abort denied because peer already transferred responsibility |

busyはcapacityが一時的でdurable stateを変更しなかった場合だけ。COMMIT_UNKNOWN、
corrupt、identity conflict、deadline terminalをBUSYへ変換しない。unknown status/stageをrejectする。

wire `TRANSFER_ABORT.abort_reason`は
`OPERATOR=1, SUPERSEDED=2, DEADLINE=3, POLICY=4`だけで、0/5/unknownをrejectする。
`EXPIRED=5`はNM30 terminal-only reasonでありwire ABORT bodyへ載せない。
resume query generationは1から開始し、新しいqueryはprevious +1 exact、最大8である。同generation/
same bodyのretryだけをidempotentとし、gap/rollback/same-generation conflictをrejectする。

## State, custody, abort, expiry, publication

### Custody invariants (no false custody / no false completion)

1. SenderはOPEN/content/manifest/chunk bytesをFULL保持してからOPENを送る。
2. ReceiverはOPEN上限・carrier mapping・policy ON・budgetを検査し、content byte数、
   1 active slot、MFDT namespace byte/key budgetを**先に予約してFULL**した後だけ
   OPEN_ACCEPTを返す。
3. 全manifest page FULL + manifest digest再計算後だけ最後のPAGE_ACCEPTで
   `manifest_complete=1`。
4. 各chunkはpayload、bitmap、record generationを同じFULL recordへcommit後だけCHUNK_ACCEPT。
5. 全chunk FULL後、canonical順whole digest検証、`content_complete=1`、
   publication `READY` token、receiver evidenceを**同一FULL**へ入れる。
6. matching FINALIZE後だけTRANSFER_ACCEPTを送る。
7. Senderはmatching TRANSFER_ACCEPTとacceptance digest FULL後だけrelease policyを実行できる。
8. CHUNK_ACCEPT / bitmap / RESUME_STATE / Radio FRAG_ACK / NFL1 success / NWB1 successを
   custody transfer completeやApplication Receiptにしない。
9. partial apply禁止: content_complete前のApplicationDataをupperへ見せない。
10. Application Receiptはexisting Foundation transactionのpositive Application resultと
    required evidence、およびmatching MFDT handoff evidenceがFULLしたことだけを意味する。
    Runtime単独のcallback exactly-onceは主張しない。

### Publication owner (exact allocation)

| role | may FULL NM3R/NM3S/NM30 | may send TRANSFER_ACCEPT | may compute publication_token | may invoke Application callback | may claim Application Receipt |
| --- | :---: | :---: | :---: | :---: | :---: |
| receiver multi-frame owner | yes (NM3R/NM30) | yes | **yes sole** | no | no |
| sender multi-frame owner | yes (NM3S/NM30) | no | no | no | no |
| relay-neutral bearer | no | no | no | no | no |
| Controller (U5) | no multi-frame kinds | no | no | no | no |
| compact RF / Wi-Fi driver | no | no | no | no | no |
| Foundation Runtime callback/reconcile owner | no multi-frame kinds | no | no | **yes sole** | no |
| upper application handoff port | no multi-frame kinds | no | no | receives callback only | **yes sole effect owner** |

publication tokenは
`SHA-256("NM3-PUBLISH-V1" || BIND52 || whole_content_sha256 ||
total_length_u32_be || receiver_evidence_id)[0..15]`で、all-zeroならinternal failureとして
READY/TRANSFER_ACCEPTを0にする。upper handoffは
publication tokenをprivate MFDT handoff/deduplication keyにする。public callbackの
`context_id`はMFDTでもFoundation transaction IDのままであり、publication tokenに
置換しない。

### Foundation Application handoff ordering（SPEC_ACCEPTED amendment, exact）

新しいoutcome state machineやcontrol exchangeを追加せず、existing Foundation
transaction/callback/reconcile/evidence/Receipt pathを次の順序で使う。

1. Receiverはverified content、whole digest、publication `READY`とnon-zero publication tokenを
   NM3Rへ`G_R_CONTENT` FULLする。
2. RuntimeはOPENのApplication bindingからcanonical Application envelopeを復元し、
   logical payload length、inline length 0、MFDT route、transfer ID、target ordinalを持つ
   inbound Foundation transactionを1件FULLする。このFULL前のcallbackは禁止する。
3. Existing callback/reconcileはFoundation transaction IDをpublic `context_id`として保ち、
   sidecarのverified whole objectをread-onlyでborrowする。publication tokenはprivate bridgeの
   handoff dedupeにだけ使う。
4. Applicationのpositive resultとevidence bytes/stageをexisting Foundation transactionへFULLする。
5. evidence stageがOPENの`required_evidence`を満たす場合だけ、下のexact digestを導出する。
6. Receiverはpublication tokenとそのdigestをNM3Rへ`PUBLISHED/HANDOFF_COMPLETE`として
   `G_R_HANDOFF` FULLする。
7. step 4と6がFULLした後だけ、existing Application Receipt pathはOPENから復元した
   original attempt、party/target、Service/family/schema、generation、evidence、target ordinalを送る。
8. Receiptのdurable closure後だけreceiverをterminalizeし、retention policyに従ってcontentを解放する。

Application evidence digestは次のSHA-256 exactである。全integerはunsigned big-endian、
domain ASCIIはNULを含めず、`evidence_length` はevidence bytesのexact長である。

```text
SHA-256(ASCII("NINLIL-MFDT-APPLICATION-EVIDENCE-V1") ||
        publication_token[16] ||
        origin_transaction_id[16] ||
        original_attempt_id[16] ||
        target_ordinal_u32_be ||
        evidence_stage_u32_be ||
        evidence_length_u32_be ||
        evidence_bytes)
```

positive Application resultであり、かつdurable evidence stageが`required_evidence`を満たす
場合だけstep 5以降へ進む。Disposition、fatal callback result、recovery fence/
outcome unknownはMFDT handoff、Receipt、terminalization、content releaseをclaimしない。
FoundationまたはMFDT FULLの`COMMIT_UNKNOWN`は両storeをcold recoveryでclassifyするまで
後続callback/wire/mutationを0にする。

Restartは次の既存stateから再開する: MFDT READY + Foundation absentはstep 2、
Foundation present + app evidence absentはstep 3、app evidence FULL + MFDT READYはstep 5、
handoff COMPLETE + Receipt openはstep 7、Receipt closedはstep 8。identity/digest/transfer/ordinal/stateの
不一致はstorage corruptionとし、callback/Receiptを0にする。

### Abort and expiry

- receiver responsibilityはupper handoff FULLまたはauthority actorによるABORT FULLだけで終了する。
- receiverがcontent complete済み、または上位へ公開済みならsender起点ABORTを拒否
  （reject code 10）。
- abort generationは同transferで1から開始し、同じreason/actorのretryは同generation、
  新semantic abortはprevious +1 exact、最大8、wrap/gap/rollbackをrejectする。
- abortのowner、reason、generation、manifest bindをactive recordとtombstoneへFULLした後だけACKする。
- reservation expiry: `now_ms >= reservation_not_after_ms`（same epoch only）で
  chunk/manifest受理をfenceする。同じFULLでactive erase + NM30
  `ABORTED/EXPIRED(5)` putを行い、NRC1をretentionまで残した後だけREJECT code 7。
  expiry後にOPENを延長せず、abort generation=0 / actor=0とする。
- senderが保持するreservation epochはpeer receiverのclock domainである。senderの
  `local_clock_epoch_id`と異なる場合、OPEN_ACCEPTの`reservation_not_after_ms`を
  senderの`now_ms`と比較してはならず、sender側local expiryも実行しない。
  expiryの確定はreceiverのterminal responseに従う。同一epochの場合だけsenderも
  上記predicateを使用できる。
- effect deadline: same epoch projectionがある場合だけearlier bound。異epoch比較禁止。
- abort race: concurrent ABORTとFINALIZEでは、先にFULLしたterminalが勝ち、後着は
  current tombstone/stateからdeterministic REJECTまたはidempotent ACKを返す。

### COMMIT_UNKNOWN

各FULLがCOMMIT_UNKNOWNならwire success/acceptを0にし、同じkeyをread-classifyする。

| classification | observed | action |
| --- | --- | --- |
| OLD | exact old bytes (single-key, or only pre-terminal active remains) | retry same FULL intent |
| NEW | exact new bytes | adopt new state; no second burn of same intent; external replay remains profile-gated below |
| ABSENT | observed empty / missing expected key | CORRUPT fence or definite retry policy per group |
| BOTH | terminal multi-key group shows active **and** NM30 members together | CORRUPT fence (exclusive erase+put violated) |
| PARTIAL | short/truncated | CORRUPT fence |
| EXTRA | unexpected extra key in group | CORRUPT fence |
| THIRD | neither old nor new exact | CORRUPT fence |

ESP format-4はpower-cut HILでFULL promotionが証明されるまでreadback一致をsuccessへ昇格しない
（本ADRはHIL成功を主張しない）。reconnect時はfresh authenticated sessionのRESUME_QUERYだけを使い、
receiver durable bitmap以外からoffsetを推測しない。

ESP target profileでpromotionがOFFなら、`NEW`のactive/NRC1/NM30はrecovery用のdurable bytesに
すぎず、同一process retryまたはcold restart後のNRC1 hitからsuccess/accept bodyを返さない。
Host FULL-capable profileの`STORAGE_OK` hit-pathは従来どおりbit-exact replay可能である。
promotion APIは、platform trust rootへbindした署名、device/build/profile identity、
anti-rollback、expiry/revocation、physical power-cut matrixを検証する実装が入るまで
**unavailable**である。magic prefix、non-zero tail、digest-shaped bytesだけをattestationとして
受理してはならない。

### Restart / resume / GC

- restartは全known keyをtemporary scan resultへ読み、**全semantic validation完了まで**
  engine slot、active count、scheduler cursor、wire replayを変更しない。
- active NM3S/NM3RはCRC/schemaだけでなく、key kind/transfer ID、owner/state closed set、
  reserved zero、record generation、offset 300 session generation、embedded OPENとの
  revision/digest/length/geometry一致、page/chunk bitmap範囲、reservation fieldの
  all-zero/all-nonzero相関、publication/handoff/evidence、abort field相関を検証する。
  repaired CRCを持つsemantic-invalid recordもrejectする。
- NRC1はkey/transfer bind、header current generation、72 slot、occupied/count/sequence、
  empty all-zero、occupied `(generation, request_id)` uniqueness、L 1..160、closed response type、
  trailing zeroを検証する。activeとNRC1 current generationはexact一致する。
- NM30は下記terminal class cross-product、key/transfer bind、CRC、retention anchorを検証する。
  同transfer IDのactive+NM30 BOTH、active without NRC1、post-terminal NM30 without NRC1、
  duplicate active sides、profile上限超過、Host store bound超過はsuccess/replay 0で
  CORRUPT fenceまたはquarantineする。
- Hostはvalid active transfer IDをunsigned lexicographic orderでslot 0..3へ割り当て、
  `next_slot=0`から新scheduler epochを始める。5件以上を切り捨てずfail closed。
- resumeはtransfer_id + manifest_digest bindのみ。bitmapはhint。
- GC: retention経過後、NM30とrelease-policy許可済みpayloadをFULL delete。
  active transferをsilent evictionしない。capacity不足は新規OPENをBUSY/REJECT。

## Durable storage candidate

### Namespace derivation and binding

Foundation Runtimeのcaller-supplied storage namespaceをexact bytes `B`（length
`L=1..255`）とする。MFDT sidecar namespace `S`は次の36 bytes exactである。

```text
S = "NMF1"
    || SHA-256(
         "NINLIL-MFDT-STORAGE-NAMESPACE-V1"
         || u16be(L)
         || B)
```

`S`はopaque bytesであり、text/path/NUL終端として扱わない。Storage `open`の
`expected_schema`は現Storage Portがsupportする
`NINLIL_STORAGE_SCHEMA_M1A (1)`を使うが、Foundation M1a record profileと
MFDT record profileを同一視しない。

同じprovider上のarbitrary caller namespaceとcryptographic derivation結果が一致する可能性を
silentに無視しない。MFDT sidecarはexactly 1つのnamespace binding rowを必須とする。

```text
key = "NMS1" || zero[16]                         # 20 bytes exact

value:
0       4      magic = "NMS1"
4       2      schema = 1
6       2      header_length = 48
8       4      total_length = 52 + L
12      2      base_namespace_length = L
14      2      flags = 0
16      32     SHA-256(
                   "NINLIL-MFDT-BASE-NAMESPACE-V1"
                   || u16be(L)
                   || B)
48      L      base_namespace exact bytes B
48+L   4      CRC32C over [0, 48+L)
```

CRC32Cはreflected Castagnoli `0x82F63B78`、initial/final XOR
`0xffffffff`である。Valueは53..307 bytes exact。Binding key/valueのmissing、
duplicate、wrong length/schema/flags/digest/base bytes/CRC、またはbinding以外のforeign
keyはsuccessへ切り捨てず`CORRUPT`である。初回empty namespaceだけがbinding rowを1回の
FULLで作れる。Binding FULLの`COMMIT_UNKNOWN`はhandleをclose/reopenして
`ABSENT`またはexact `NEW`だけを分類し、`PARTIAL/EXTRA/THIRD`はfenceする。

このbindingにより、callerが偶然`S`と同じFoundation namespaceを選んだ場合も、
別の`B`が同じderived namespaceへ到達した場合も、既存bytesを上書きせずfail closedになる。
Derived namespaceの衝突不能性を暗黙に仮定しない。

### Record catalog

派生MFDT namespaceへ次の **4** transfer kindを追加する。keyはいずれも20 bytes
`kind[4] || transfer_id[16]`である。`NMS1` bindingはtransfer kind/countへ含めない。

| kind | owner | value |
| --- | --- | --- |
| `NM3S` | sender active/evidence | canonical sender active record schema 2 |
| `NM3R` | receiver reservation/manifest/chunks/publication | canonical receiver active record schema 2 |
| `NM30` | completed/aborted/corrupt terminal tombstone | canonical terminal record schema 2（schema 1はlegacy replay-ineligible） |
| `NRC1` | responder request-ID response cache | fixed 15020-byte 72-slot cache; retained until NM30 GC (see §Request-ID) |

ESP profileは同時active MFDT v1 transferをdirection合計1とし、active recordは1 key + NRC1 1 key、
terminal transitionで **active delete + NM30 put**（NRC1は残置）を同一FULL final viewにまとめ、
retention GCで NM30 delete + NRC1 deleteを同一FULLにする。terminal stagingは最大3 keys
（active+NRC1+NM30）。Bindingを含むMFDT namespaceが
32 keys/69632 logical bytesを超えるadmissionはstate mutation 0でBUSY/REJECTする。
MFDT用に active+NRC1+terminal staging（最大3 key /
35247+15056+216 = **50519**）を予約できない場合はOPENを受けない。
retention中は NM30+NRC1（2 key / **15272**）を維持する。
Foundation/U6/ARW rowはこのcapacityへ混在させない。Host profileはbinding 1 keyに加えて
transfer rows 32 keysまで、合計33 keysを要求する。

NM3S/NM3R schema 2は単一canonical valueにheader、exact TRANSFER_OPEN body、全manifest entry、
bitmap、content bytesを保持する。missing pageのentry領域と未受信chunkのcontent領域はcanonical
zeroで、page/chunk bitmapだけがpresent authorityである。zero-filled実chunkとはbitmapで区別する。
headerは308 bytes exact:

```text
offset  bytes  field
0       4      magic = key kind ("NM3S" or "NM3R")
4       2      active schema = 2
6       2      header_length = 308
8       4      total_record_length
12      1      owner_side: SENDER=1, RECEIVER=2
13      1      state_code
14      2      flags = 0
16      16     transfer_id = key id
32      4      manifest_revision
36      32     manifest_digest
68      8      record_generation, >=1 exact +1 per semantic FULL update
76      8      acceptance_record_generation; zero until content-verified FULL
84      2      open_body_length, 465..651
86      2      manifest_entries_length = 40 * chunk_count
88      4      content_length = OPEN total_length
92      2      chunk_count
94      2      manifest_page_count
96      8      chunk_progress_bitmap
104     1      manifest_page_bitmap; bits >= page_count zero
105     1      retry_budget_remaining, 0..8  # see §Retry budget state machine
106     1      release_policy: IMMEDIATE=0, AFTER_RETENTION=1, HOLD=2
107     1      publication_state: NONE=0, READY=1, PUBLISHED=2
108     1      handoff_state: NONE=0, COMPLETE=1
109     1      accept_notified: 0 or 1
110     2      reserved0 = 0
112     16     reservation_id; zero before OPEN accepted, otherwise non-zero
128     16     reservation_clock_epoch_id; same zero/non-zero state as reservation_id
144     8      reservation_not_after_ms; same zero/non-zero state as reservation_id
152     16     receiver_evidence_id; zero until receiver final FULL
168     32     acceptance_record_digest; zero until receiver final FULL
200     16     local_clock_epoch_id
216     8      local_mono_ms
224     4      abort_generation; zero when no abort
228     2      abort_reason; zero iff abort_generation zero
230     2      reserved1 = 0
232     16     authority_actor_id; zero iff abort_generation zero
248     16     publication_token; zero before READY
264     32     publication_evidence_digest; zero before PUBLISHED
296     4      last_resume_query_generation; 0..8
300     4      session_generation; active時non-zero、NRC1 current generationと一致
304     4      header_crc32c over bytes [0,304)
308     O      exact TRANSFER_OPEN body
308+O   E      manifest entry slots, E=40*chunk_count
308+O+E L      content slots, L=content_length
308+O+E+L 4    record_crc32c over all preceding record bytes
```

OPENの3 textが各1 byte以上なのでminimum open bodyは`462+3=465`である。
maximum exact NM3S/NM3R valueは
`308 + 651 + 37*40 + 32768 + 4 = 35211` bytesで、single value 65536以下である。
active schema 1はbaseline履歴としてのみ扱い、cold restart/replay/migration/admissionはすべて0で
fail closedにする。OPEN lengthの範囲からschema/revisionを推測しない。active schema 2は
NM30 terminal schema 2とkindが異なるため、両schemaを同じrecord layoutと解釈しない。
headerのtransfer/revision/manifest/content/chunk/page fieldはembedded OPENとbit-exact一致し、
OPEN bodyのderived count/digest検査も毎readで繰り返す。variable offsetは上式からchecked導出し、
gap、overlap、short、trailing、CRC不一致をCORRUPTとしてwire success 0にする。

state codeはsideごとのclosed setである。**Durable active NM3S/NM3R records use only the
non-terminal codes below.** Codes formerly labeled terminal-on-active
(`S_TERMINAL_COMPLETE=7`, `S_TERMINAL_ABORTED=9`, `R_ABORTED=39`) are **removed / unreachable
as durable active storage**: after `G_*_TERMINAL` FULL the active key is erased and only
NM30 remains. In-memory process labels may use those names transiently **before** the
terminal FULL returns, but they must never be written as durable NM3S/NM3R state codes.

| side | code | state / mandatory invariant (durable active only) |
| --- | ---: | --- |
| sender | 1 | `S_OPEN_PENDING`: content/全entry present、progress=0、reservation/evidence zero |
| sender | 2 | `S_OPEN_ACCEPTED`: reservation non-zero、manifest page send可 |
| sender | 3 | `S_MANIFEST_ACCEPTED`: page bitmap all-set、chunk send可 |
| sender | 4 | `S_CHUNKS_PARTIAL`: progressはFULL保存済みCHUNK_ACCEPTだけ |
| sender | 5 | `S_FINAL_WAIT`: progress bits 0..chunk_count-1 all-set |
| sender | 6 | `S_ACCEPT_RX`: receiver evidence/digest/generation non-zero、payloadはrelease policyまで保持；次のFULLは`G_S_TERMINAL` |
| sender | 8 | `S_ABORT_PENDING`: responsibility未移転、abort generation/reason/actor FULL；次のFULLは`G_S_TERMINAL` |
| sender | 10 | `S_COMMIT_UNKNOWN`: wire success 0、read-classifyだけ |
| receiver | 32 | `R_RESERVED_OPEN`: reservation FULL、page/chunk bitmap 0 |
| receiver | 33 | `R_MANIFEST_PARTIAL`: page bitmap non-zeroだがnot all |
| receiver | 34 | `R_MANIFEST_ACCEPTED`: all pages/digest verified、chunk受理可 |
| receiver | 35 | `R_CHUNKS_PARTIAL`: chunk progress not all |
| receiver | 36 | `R_CONTENT_VERIFIED`: all bits、whole digest、publication token READY、acceptance evidence/generation non-zero |
| receiver | 37 | `R_ACCEPT_NOTIFIED`: accept_notified=1、responsibility保持 |
| receiver | 38 | `R_HANDED_OFF`: handoff COMPLETE；次のFULLは`G_R_TERMINAL`（active erase + NM30） |
| receiver | 40 | `R_COMMIT_UNKNOWN`: wire success 0、read-classifyだけ |
| receiver | 41 | `R_ABORT_PENDING`: authority abort intent FULL on active fields, publication NONE；次のFULLは`G_R_TERMINAL` |

**Terminal durability is NM30-only** (`COMPLETE` / `ABORTED` / `CORRUPT_FENCED`). There is
never a legal durable image with both active NM3S/NM3R and NM30 for the same transfer
(BOTH ⇒ CORRUPT fence). Crash images for `G_*_TERMINAL`:

| crash observed | classification | action |
| --- | --- | --- |
| only pre-terminal active (6/8/38/41) | OLD | retry same terminal FULL intent |
| only NM30 exact | NEW | adopt terminal; no second burn |
| active **and** NM30 | BOTH | CORRUPT fence |
| empty / short / third | ABSENT/PARTIAL/THIRD | CORRUPT or definite policy per group |

Vectors: `MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE`, `MF-TX-TERMINAL-CRASH-ACTIVE-ONLY`,
`MF-TX-TERMINAL-CRASH-NM30-ONLY` (plus existing `MF-CU-TERMINAL-GROUP-*`).

stateと矛盾するbitmap、reservation、publication、handoff、accept/evidence fieldはCORRUPTである。
sender progress bitmapはmatching CHUNK_ACCEPTのsender側FULL evidence、receiver progress bitmapは
chunk bytesのreceiver側FULLだけを表す。同じbitをraw wire観測だけで立てない。
durable active recordの`state` fieldが7/9/39を含むならCORRUPT（unreachable codes）。

canonical NM30 writerはschema 2 / 180 bytes exactを出力する:

```text
0/4 magic="NM30"; 4/2 schema=2; 6/2 value_length=180;
8/16 transfer_id; 24/4 manifest_revision; 28/32 manifest_digest;
60/2 terminal_state; 62/2 terminal_reason; 64/4 abort_generation;
68/16 receiver_evidence_id; 84/32 acceptance_record_digest;
116/16 authority_actor_id; 132/16 retention_anchor_clock_epoch_id;
148/8 retention_anchor_mono_ms; 156/16 peer_endpoint_id;
172/1 owner_role (SENDER=1, RECEIVER=2); 173/3 reserved=0;
176/4 crc32c over [0,176)
```

`peer_endpoint_id`はnon-zeroで、terminal FULL直前のcanonical active OPENからlocal
owner roleに対応するremote endpointをbit-exact copyする。`owner_role`はterminal rowを
保持するlocal owner sideである。session cookieは接続ごとのvolatile secretなのでNM30へ
保存しない。terminal groupのcurrent session generation authorityは、必ず併存するNRC1
header offset 24のnon-zero値であり、NM30へ重複保存しない。

legacy schema 1 / 164-byte NM30（156/4 reserved=0、160/4 CRC over `[0,160)`）は、
既存媒体の課金とretention GCに限りcanonical validationできる。peer/roleを持たないため
cold replay、rebind、wire response、transport `OK`のauthorityにはならず、Host catalogでは
`replay_ineligible`とする。schema 1からpeer、role、cookieをNRC1 bodyやcaller inputから
逆算・推測してはならない。新規writer、repair、再terminal化でschema 1を生成しない。

この境界はmachine vectors
`MF-POS-NM30-SCHEMA2-LAYOUT-KAT`、
`MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY`、
`MF-TX-HOST-TERMINAL-COLD-REBIND-HIT`、
`MF-NEG-HOST-TERMINAL-BIND-MATRIX`、
`MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT`、
`MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY`、
`MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE`、
`MF-NEG-PREADMISSION-POLICY-STATELESS`、
`MF-NEG-PREADMISSION-DEADLINE-STATELESS`、
`MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED`
でbyte、ownership、FULL count、bind mismatch、no-mutationを固定する。

terminal stateは`COMPLETE=1, ABORTED=2, CORRUPT_FENCED=3`だけ。COMPLETEはreceiver evidence/
acceptance digest non-zeroかつterminal reason/abort generation/actor zeroである。
ABORTEDは次の2 classだけである。

- authority/user abort: reason 1..4、abort generation 1..8、actor non-zero、
  receiver evidence/acceptance digest zero
- automatic reservation/effect expiry: terminal-only `EXPIRED=5`、
  abort generation 0、actor zero、receiver evidence/acceptance digest zero

CORRUPT_FENCEDはterminal reason `0x8001`（generic storage corrupt）または
`0x8002`（`EPOCH_CHANGED`）、abort generation 0、actor zeroで、automatic payload releaseを
禁止する。receiver evidenceとacceptance digestは両方zero、またはcontent verification後に
activeからbit-exact copyされた両方non-zeroだけを許す。
全terminal classでretention anchor epochはnon-zero、anchor monotonic値はterminal FULL前の
trusted sample exactであり、durationをanchor fieldへ格納してはならない。
active→terminalは同一FULL final viewでactive keyをeraseしNM30をputする（active上に
S_TERMINAL_* / R_ABORTED を残さない）。**NRC1はこのFULLではeraseしない**（late-duplicate
bit-exactのため retention GCまで保持）。COMMIT_UNKNOWNはactive-oldまたはNM30-newをfull
compareし、両方/missing/partialをCORRUPT fenceする。

MFDT sidecar scannerはbinding `NMS1`とkey length 20の
`NM3S/NM3R/NM30/NRC1`だけをknown kindとして受理し、wrong key length、
magic/key mismatch、NM3S/NM3R active schema 1/unknown schema、Foundation/U5/U6/ARW rowを
foreign/corruptとして
隔離する。Foundation Runtime scannerへMFDT kindを追加せず、large-valueをskipするための
reread/temporary allocationも追加しない。

最大active row logical bytesは`16 + key20 + value35211 = 35247`、NRC1 rowは
`16 + 20 + 15020 = 15056`、canonical terminal rowは
`16 + 20 + 180 = 216`。MFDT admissionはcommitted active 1 key/35247 +
NRC1 1 key/15056 と、terminal transition staging用追加1 key/216、
合計最大3 entry / **50519** bytesを予約する。ESP MFDT namespaceではbinding rowを含む
finalが32 keys/69632 bytes、begin+final unionが64 entries/139264 bytes以下であることを
storage transaction開始前に検査する。active maximum replacementのbegin+final logical bytesは
`35247 * 2 = 70494`で139264以下である。境界exact、+1はstate mutation 0でCAPACITY rejectする。
NRC1 value 15020 &lt; 65536 single-value limit。

### Foundation NTS3 correlation amendment（SPEC_ACCEPTED normative amendment）

MFDT-backed Applicationをcold restart後に同じFoundation transactionとtargetへ戻すため、
current private NTS3 schema 1.1の**future schema minorは1.2へ進める**。in-memoryの各canonical
target slotが常に持つ追加fieldは次の2つだけである。

```text
mfdt_transfer_id[16]
mfdt_target_ordinal_u32
```

schema 1.2 recordではtransaction `bearer_route == MFDT_V1 (3)`の場合だけ、各canonical target
encodingの**末尾**へ`mfdt_transfer_id[16]`、続いて`mfdt_target_ordinal_u32_be`を20 bytes exactで
appendする。sender origin transactionはcanonical roster順の1..4 targetすべてにsuffixを持ち、
各transfer IDはnon-zero、ordinalはそのbound-targetのzero-based canonical array indexとexact一致する。
receiver inboundはtarget count 1で同じsuffix encodingを使うが、ordinalにはOPENのorigin roster
ordinal（0..3）を保持する。receiver local target array index 0へ書き換えず、0との一致も要求しない。
追加presence flagは設けない。

`bearer_route != MFDT_V1 (3)`では20-byte suffixをrecordへ一切encodeしない。decode後のin-memory
fieldはtransfer ID all-zero / ordinal zeroでなければならず、encode入力も同じzero/zeroだけを許す。
schema minor 1.2とbearer routeがsuffix presenceを一意に決めるため曖昧性はない。1.2を有効化した
codecはschema 1.1またはunknown minorを1.2として解釈せずfail closedし、implicit migrationしない。

record ceilingは4096 bytesを維持する。現行schema 1.1全valid field worst caseは4031 bytes、
MFDT routeはinline payload 0なので最大inline 926 bytesを除き、最大4 targetのsuffix 80 bytesを
加えて`4031 - 926 + 4 * 20 = 3185 <= 4096`となる。non-MFDT schema 1.2はsuffixをencode
しないため4031 bytesのままである。implementation acceptanceは4-target MFDT 3185-byte
round-trip、1 byte不足のBUFFER_TOO_SMALL、suffix順序、各ordinal、non-zero transfer ID、
non-MFDT suffix不在とdecode後zero/zeroを検査する。

`delivery_context_id`、publication token、Application binding、sidecar offset、新しいoutcome fieldを
NTS3へ重複追加しない。public callback `context_id`はFoundation transaction IDのままである。
本amendmentはschema 1.2のnormative仕様だけを固定し、NTS3 production codec/API/CMakeの変更やmigration完了を
主張しない。

### Cross-namespace admission, restart, and teardown

Foundation namespaceとMFDT sidecar namespaceを跨ぐatomic transactionは存在しない。
MFDT V1 admissionだけは、canonical exact target rosterを確定した直後、attempt entropyを
1回も呼ぶ前に、全targetの`target_runtime_id`が相互にuniqueであることを要求する。同じRuntimeを
指すtargetが2件あれば、Application instance IDが同じでも異なっていても、既存unsupported-roster
分類 `NINLIL_OK` + submission `REJECTED / TARGET_COUNT_UNSUPPORTED`とする。entropy call、sidecar
mutation、Foundation mutationはすべて0であり、複合receiver keyや例外的なtarget identityを作らない。
この追加guardはMFDT V1だけに適用し、NTS3のtarget-local transfer ID / origin ordinal suffix規則は
変更しない。

owner-threadの同じadmission call内では次の順序だけがvalidである。

1. Public admissionのtransaction ID candidateとcanonical exact target rosterを確定し、上記
   same-Runtime duplicate guardを通す。
2. canonical target順に各targetのApplication attempt ID candidateを選ぶ。1 targetにつき
   `entropy.fill(16)`は最大4 drawで、Port failure、partial、all-zero、collisionを各1 drawとして
   数える。collision setはdurable active/retained attempt-ID indexに加え、このadmission call内で
   先に選択済みのtarget candidateを含む。valid candidateはnon-zeroかつこの集合にuniqueである。
3. 各candidateをそのtarget専用OPENの`original_attempt_id`へbit-exactに入れ、導出済みnon-zero
   transfer IDとorigin roster ordinalをbindしたsender `NM3S+NRC1` armをMFDT sidecarへFULLする。
   各targetをstep 2→3の順で処理し、全target armがdurable `NEW`になるまでwire、TxGate acquire、
   callbackは0である。sidecar pre-armだけをFoundation/publicの「attempt消費済み」、budget/counter
   消費、`ATTEMPT_PREPARED`として投影しない。
4. 全required armがdurable `NEW`になった後だけFoundation admission groupを**exactly 1 FULL**
   する。同じFULLでexact roster、各targetのattempt index/binding、attempt budget/counters、既存
   `ATTEMPT_PREPARED` / pending state、MFDT transfer ID / origin ordinalをatomicにcommitする。
   このFULLが`OK`になるまでwire、TxGate acquire、callbackは0である。新しいstate/kind/APIは加えない。
5. candidate max-4 exhaustionまたはarm FULLのdefinite failureではFoundation admission FULLを0とし、
   それ以前に作成済みのarmだけをbounded cleanup FULLする。arm FULLの`COMMIT_UNKNOWN`、または
   cleanup `COMMIT_UNKNOWN`は成功/rejectをclaimせずRuntimeをfenceしてcold reconcileへ送る。
6. Foundation FULLがdefinite failureなら全armをbounded cleanup FULLでdisarmする。
   Foundation FULLが`COMMIT_UNKNOWN`ならsidecarを削除せずwire/application successを0にして
   Runtimeをfence/closeする。次createだけが両namespaceを照合する。

未解決のarm/Foundation `COMMIT_UNKNOWN`、restart、public API replayではattempt candidateを
盲目的に再drawしない。Foundation commitが確認できれば同じattempt/OPEN/armを再開し、Foundation
absentが確認できればorphan armをcleanupする。全候補はFoundation FULL `OK`までpublic/durableな
「消費済みattempt」と主張しない。Restart reconciliationは既存Foundation T0–T6とsidecar照合を
Bearer open前に行えるため、このordering専用の新しいdurable stateは不要である。

RestartはFoundation T0–T6 recoveryを先に完了し、その後Bearer open/publication前に
MFDT sidecarをopen/recoverする。照合結果はclosedである。

| Foundation transaction | matching sidecar arm | Result |
| --- | --- | --- |
| exact MFDT nonterminal | all target-local exact rows | resume eligible |
| exact MFDT nonterminal | missing/mismatch/extra target row | CORRUPT fence; dispatch/apply 0 |
| absent | orphan sidecar arm | bounded orphan cleanup FULL; wire/apply 0 |
| non-MFDT or terminal incompatible | sidecar active | CORRUPT fence |
| partial/third/unknown either side | any | CORRUPT fence |

Orphan cleanupの`COMMIT_UNKNOWN`はOLD/NEW/ABSENT/PARTIAL/EXTRA/THIRDをsidecar内で
read-classifyする。Foundation bytesからsidecar contentを再生成せず、sidecar bytesから
Foundation admission成功を推測しない。Receiver publication/Service callback/Application
Receiptは両側exact matchとreceiver-side content verificationの後だけである。

MFDT-ONのproduction compositionはこのsidecar open/recoveryをRuntime createの
Bearer openより前へ組み込む。Live Runtimeへ後付けするprivate configure seamはtest-onlyで、
release/public API completionの根拠にしない。Destroy/failed-createのhandle close順は
`Bearer -> MFDT sidecar -> Foundation storage`で、各handle exactly once、live txn/iterator 0。

### Foundation FULL budget (replaces impossible 80 FULL/day)

Per-chunk FULL durabilityを弱めない。obsolete claim
「ESP reference profileはv3によるFULLを80/day以下、最大32768-byte transferを2/day」は
**物理不能**として破棄する（receiver max-size 2 transfers × **77** FULL = **154** > 80）。

Exact FULL group counts for one **max-ID COMPLETE path** (`total_length=32768`,
`chunk_count=37`, `page_count=2`, full RESUME + ABORT_DENIED + timeout REQID +
RETRY_BUDGET + SESSION_GEN envelopes) — **sole authority**, matches §FULL ordering /
budget above and machine vector pins (77/67, daily 154/134). Earlier conflicting
arithmetic is **void**:

| group id | owner | FULL count | members |
| --- | --- | ---: | --- |
| `G_R_OPEN` | receiver | 1 | reservation + OPEN bind + NRC1 OPEN slot |
| `G_R_PAGE` | receiver | 2 | each manifest page + NRC1 PAGE slot |
| `G_R_CHUNK` | receiver | 37 | each chunk + NRC1 CHUNK slot |
| `G_R_CONTENT` | receiver | 1 | whole digest + READY token + evidence |
| `G_R_ACCEPT` | receiver | 1 | accept_notified after FINALIZE + NRC1 FINALIZE slot |
| `G_R_HANDOFF` | receiver | 1 | PUBLISHED + handoff COMPLETE |
| `G_R_TERMINAL` | receiver | 1 | **active erase + NM30 put** (NRC1 retained) |
| `G_R_RESUME` | receiver | 8 | RESUME first-attempts + NRC1 |
| `G_R_REQID_CACHE` | receiver | 16 | ABORT_DENIED×8 + timeout new-ID NRC1-only×8 |
| `G_R_RETRY_BUDGET` | receiver | 8 | owner FULL for retry_budget_remaining decrement |
| `G_R_SESSION_GEN` | receiver | 1 | session_generation reclaim FULL |
| **receiver total** |  | **77** | max-ID COMPLETE path (=44+8+16+8+1) |
| `G_S_OPEN` | sender | 1 | content+manifest before OPEN wire |
| `G_S_OPEN_RX` | sender | 1 | OPEN_ACCEPT reservation capture |
| `G_S_MANIFEST` | sender | 1 | all pages accepted |
| `G_S_CHUNK` | sender | 37 | each CHUNK_ACCEPT evidence |
| `G_S_ACCEPT` | sender | 1 | TRANSFER_ACCEPT capture |
| `G_S_TERMINAL` | sender | 1 | release policy + active erase + NM30 (NRC1 retained) |
| `G_S_RESUME` | sender | 8 | RESUME_QUERY first-attempts |
| `G_S_REQID_CACHE` | sender | 8 | sender-as-responder NRC1-only first bodies |
| `G_S_RETRY_BUDGET` | sender | 8 | owner FULL for retry_budget_remaining decrement |
| `G_S_SESSION_GEN` | sender | 1 | session_generation reclaim FULL |
| **sender total** |  | **67** | max-ID COMPLETE path (=42+8+8+8+1) |
| `G_*_RETENTION_GC` | either | 1 | post-retention NM30+NRC1 dual delete (not in transfer max) |

Empty transfer (`total_length=0`): receiver FULL = `G_R_OPEN(manifest_complete=1) + G_R_CONTENT + G_R_ACCEPT + G_R_HANDOFF + G_R_TERMINAL` = **5**。
sender FULL = `G_S_OPEN + G_S_OPEN_RX + G_S_MANIFEST(no pages) + G_S_ACCEPT + G_S_TERMINAL` = **5**。
(empty path does not charge RESUME/ABORT_DENIED/timeout/RETRY/SESSION envelopes.)

Foundation profile arithmetic (exact, machine-checked):

```text
mf_policy_default = OFF
mf_max_active_esp = 1
receiver_fulls_max_transfer = 77
sender_fulls_max_transfer = 67
receiver_fulls_empty_transfer = 5
sender_fulls_empty_transfer = 5

# Device acting as receiver for N max-size transfers/day:
required_mf_fulls_receiver_day(N) = 77 * N
# Device acting as sender for N max-size transfers/day:
required_mf_fulls_sender_day(N) = 67 * N

# Admission before OPEN:
planned_domain_fulls_per_day >= baseline_non_mf_fulls_per_day
    + required_mf_fulls_(role)_day(planned_mf_maxsize_transfers_per_day)
else REJECT capacity (code=5), state mutation 0.
```

Reference numbers pinned by vectors:

| profile pin | value |
| --- | ---: |
| obsolete_rejected_mf_fulls_per_day | 80 |
| planned_mf_maxsize_transfers_per_day_reference | 2 |
| required_receiver_fulls_for_reference | 154 |
| required_sender_fulls_for_reference | 134 |
| receiver_fulls_max_transfer | 77 |
| sender_fulls_max_transfer | 67 |
| minimum_domain_planned_fulls_when_mf_receiver_ref | baseline + 154 |
| minimum_domain_planned_fulls_when_mf_sender_ref | baseline + 134 |

Default OFF時は`planned_mf_maxsize_transfers_per_day = 0`で追加FULL要求0。
multi-frameをONにするconfigは上式を満たすwear domain budgetを明示する。
既存U5/U6 single-frame trafficのbudgetをstealしてsuccessを維持しない。

## Source-only private exact API candidate

Public ABI / installed header採番はしない。source-only private candidate:

| symbol prefix | `ninlil_mfdt_v1_` |
| --- | --- |
| ownership | caller-owned workspace + Runtime private owner objects; ESP durable-store binding/transaction/read-back state belongs to its explicit lab-store owner; no request-time heap growth |
| workspace | per active slot exact 65536 bytes、8-byte aligned。Host owner aggregate 280064 bytes（4 active arena + 17920-byte control arena） |
| zero-copy rules | offer path may borrow caller chunk bytes until the corresponding FULL returns; after FULL, store is copy-owned. Accept path never borrows peer wire buffer beyond the call. |
| concurrent transfers | ESP 1 / Host 4 as above |
| scheduling | single outstanding unpaid CHUNK_OFFER per peer quantum; fairness round-robin among Host's active transfers |
| cancellation | local cancel => ABORT reason POLICY or OPERATOR; no silent drop of durable custody |
| terminal | COMPLETE / ABORTED / CORRUPT_FENCED only |

Candidate operations (private, default-OFF):

1. `sender_open` / `receiver_on_open`
2. `sender_offer_manifest_page` / `receiver_on_manifest_page`
3. `sender_offer_chunk` / `receiver_on_chunk`
4. `sender_finalize` / `receiver_on_finalize`
5. `sender_on_accept`
6. `owner_abort` / `peer_on_abort`
7. `sender_resume_query` / `receiver_on_resume_query`
8. `receiver_poll_publication` / `receiver_complete_handoff`
9. `classify_commit_unknown`
10. `gc_tombstones`

Controller roleはU5 assignmentのみ。multi-frame open/accept/publishをController APIへ混ぜない。
relay-neutral bearerはbyte carriageのみ。false custody completionを返さない。

## Compatibility, default-OFF, rollback

- multi-frame critical capability = MFN1 admission profile revision 2 transcript成功 **and** local policy ON
  **and** exact capability bits **and** carrier MAPPING_CANDIDATE。
- MFN1非対応peerにはU6 v2 single-frameだけを提示し、926-byteを超えるApplicationDataは
  明示拒否する。base control version 1/2からMFDT対応可否を推測しない。
- MFDT transfer途中でpolicy OFF / session rebindへin-place downgradeしない。
- U6/Foundation recordとMFDT recordは別namespace/handleへ分離する。Radio FRAG stateを
  どちらへも混入させない。
- rolling update: 既存U6 v2 transferをv2で完了/期限終了し、MFDTへin-place変換しない。
- rollback: (1) policy OFF (2) in-flight complete/abort (3) fresh control session (4) NM3* keysは
  retention GCまで残置、v2 codecはunknown kindとしてignore/quarantine。
- irreversible schema migration後のold binary openは明示拒否する。
- default compile/runtime: multi-frame admission OFF。HELLOのmax versionはMFDT policyに
  関係なくAccepted 1/2だけ。MFN1はprivate feature ON時だけemitする。

## Dependencies

M1a restart-safe kernel、M3 FULL storage、U6 v2 single-frame conformance、
bounded transfer logical APIを前提とする。Radio/Wi-Fi経路のmulti-frame controlは
MAPPING_UNAVAILABLEのままなので、本候補はNCL1 control plane（典型: USB control path /
generic Fabric control plane）上のstorage crash matrixと並行SPECできる。
compact RF/Wi-Fi mappingは別ADR。

## Machine authority

| artifact | role |
| --- | --- |
| `spec/vectors/multi-frame-durable-transfer-spec-v1.json` | current SPEC_ACCEPTED amendment bytes/IDs/arithmetic; baseline promotion record is retained separately |
| `tools/multi_frame_durable_transfer_spec_vector_gen.py` | oracle generator write/check/self-test |
| `tools/multi_frame_durable_transfer_spec_gate.py` | independent Python semantic gate |
| `tools/multi_frame_durable_transfer_spec_gate.mjs` | independent Node semantic gate |
| `tests/model/multi_frame_durable_transfer_c_gate_test.c` | independent C11 gate + literal byte KATs |
| `tests/model/multi_frame_durable_transfer_c_authority.h` | C literal authority (IDs/status/KAT bytes) |
| `tools/multi_frame_durable_transfer_acceptance_gate.py` | acceptance manifest: work/CMake/4-tool bind |

Gates must not import the generator. C gate must not derive KAT expected bytes from
generator functions or vector-taught expected fields at runtime — literals are fixed in
`multi_frame_durable_transfer_c_authority.h`. Mutations repair CRC/digest to reach the
intended semantic branch. Required-ID inventories reject missing/extra/duplicate/
substituted IDs. Every required ID has fixed semantic expected data independently asserted.

Top-level machine metadata (`schema`/`status`/`adr`/`title`/`nonclaims`/`sources` and
source content digests) is independently hard-pinned in generator and Python/Node gates
and is part of the authority seal. Gates do not learn these values from the vector.

Acceptance gate additionally hard-pins the retained baseline promotion record, current amendment
work Status (**SPEC_ACCEPTED / implementation incomplete**), exact CMake test names/count (10), four authority tool
paths, and tests-OFF / noninstall.

### CMake SPEC_ACCEPTED amendment design focused tests (live; not implementation completion)

Dedicated authority file: [`cmake/ninlil_mfdt_ctest.cmake`](../../cmake/ninlil_mfdt_ctest.cmake)
(included from root CMakeLists under tests-ON). Acceptance pins that file and its
canonical test/target inventory — **not** whole-repo `CMakeLists.txt`.

Under `NINLIL_BUILD_TESTS`, CMake registers exactly these **ten** tests (no multi-frame
production library target is claimed by this ADR; not present under tests-OFF install):

1. `multi_frame_durable_transfer_vector_oracle`
2. `multi_frame_durable_transfer_vector_oracle_self_test`
3. `multi_frame_durable_transfer_python_gate`
4. `multi_frame_durable_transfer_python_gate_self_test`
5. `multi_frame_durable_transfer_node_gate`
6. `multi_frame_durable_transfer_node_gate_self_test`
7. `multi_frame_durable_transfer_c_gate`
8. `multi_frame_durable_transfer_c_gate_self_test`
9. `multi_frame_durable_transfer_acceptance_gate`
10. `multi_frame_durable_transfer_acceptance_gate_self_test`

## Implementation / release acceptance remaining

1. cross-language KAT for zero/1/max payload、final chunk boundaries、max chunks
2. reorder、duplicate、loss、gap、conflict、truncation、resource exhaustion、fairness
3. crash injection at every FULL group; COMMIT_UNKNOWN OLD/NEW/partial/extra/third
4. abort races、expiry boundary、stale generation/version、completion/receipt replay
5. partial apply 0、false custody 0、duplicate application effect 0 under upper contract
6. MFN1未成立/stale/conflict reject、U5/U6 Accepted bytes不変
7. POSIX 2-process、USB control transport、process restart、soak
8. ESP power-cut HIL、storage pressure/wear report under explicit budget arithmetic
9. docs/23/25/26とADR-0006のbyte-exact freeze non-interference、
   docs/06・docs/34・本ADRのSPEC_ACCEPTED reference整合、independent review
10. generator `--check`/`--self-test`、Python/Node/C independent semantic gate、
    RED→GREEN contract acceptance
11. derived namespace/binding KAT、caller-base collision/different-base digest collision
    simulation、binding missing/duplicate/foreign/wrong CRC、binding bootstrap FULL
    COMMIT_UNKNOWN ABSENT/NEW/PARTIAL/EXTRA/THIRD
12. every cross-namespace cut point（0..4 target pre-arm、Foundation FULL before/after/CU、
    definite failure cleanup、orphan cleanup CU）、cold restart reconciliation、
    Bearer→sidecar→Foundation exact-once teardown

## Consequences

長いApplicationDataを再開可能かつpartial applyなしで運べる。代わりにprivate MFN1、
manifest/chunk storage、二重のfragmentation境界、明示FULL budget、power-cut matrixが必要。
U6 v2の単純さと互換性はそのまま維持される。compact RF/Wi-Fi multi-frameは
別mappingまで利用不能。

## Rejected alternatives

- U6 v2 OFFERを暗黙にmanifestへ再利用する
- silent `selected >= 2`でU5/U6/v3を解釈する
- RAM reassembly後すぐTransfer Acceptを返す
- Radio FRAG_ACK / NFL1 successをdurable chunk custodyとみなす
- receiver bitmapなしに最後に見たoffsetから再開する
- storage不足時に古いchunkをsilent evictionする
- 80 FULL/dayのままmax-size 2 transfers/dayを主張する
- per-chunk FULLをbatchしてdurabilityを弱める
- NFL1/NWB1/NRW1へcontrol custody messageを載せる
- compact RF/Wi-Fi mappingを未定義のまま利用可能と書く
- hash treeをwhole digestの代わりに必須化する（v1はwhole + per-chunk list）

## Normative happy-path stage trace S1–S6

Machine-readable pin: vector `MF-TRACE-S1-S6-HAPPY-PATH`. Stages are logical; each
arrow that says FULL requires a Foundation FULL group success before wire success.

```text
S1 OPEN
  sender: S_OPEN_PENDING --OPEN--> receiver R_RESERVED_OPEN (G_R_OPEN FULL)
  response OPEN_ACCEPT; request-id cache stores OPEN_ACCEPT body
S2 MANIFEST
  for each page: MANIFEST_PAGE FULL (G_R_PAGE) -> PAGE_ACCEPT (complete 0 until last)
  same request_id late-dup -> cached PAGE_ACCEPT; new request_id may advance complete
  end: R_MANIFEST_ACCEPTED / S_MANIFEST_ACCEPTED
S3 CHUNKS
  for each index: CHUNK_OFFER FULL (G_R_CHUNK) -> CHUNK_ACCEPT
  end: R_CONTENT_VERIFIED + publication_token READY (no Application callback yet)
S4 FINALIZE / ACCEPT
  TRANSFER_FINALIZE -> G_R_ACCEPT path + TRANSFER_ACCEPT evidence
  sender: S_ACCEPT_RX (active, not terminal)
S5 HANDOFF
  Foundation inbound transaction FULL -> callback/reconcile with Foundation transaction context
  positive required evidence FULL -> exact evidence digest -> G_R_HANDOFF FULL -> Receipt closure
  disposition/fatal/recovery fence: remain in custody; no handoff/Receipt/release
S6 TERMINAL (NM30 only)
  G_R_TERMINAL / G_S_TERMINAL: erase active + put NM30 COMPLETE; NRC1 retained until GC
  late-duplicate (post-terminal): NRC1 hit bit-exact until G_*_RETENTION_GC
  G_*_RETENTION_GC: erase NM30 + NRC1
  durable image: NM30 only (no S_TERMINAL_* / R_ABORTED active codes)
```

Abort and epoch-change branch from any active state into `R_ABORT_PENDING` /
`S_ABORT_PENDING` or direct CORRUPT_FENCED terminal FULL per rules above; never leave
active+NM30 dual truth.

## Open evidence register

| ID | OPEN | close condition |
| --- | --- | --- |
| MF-O01 | Accepted freeze vs private MFDT negotiation baseline | **SPEC_ACCEPTED / GREEN HISTORY** — Accepted control versionは1/2のみ。baseline revision 1のpromotion/review記録は変更しない。 |
| MF-O02 | default-OFF software candidate | **GREEN / private software candidate** — repaired contractのHost4 routing、ABORT/NM30、deadline/overflow、restart semantic validation、retention GCを通常/Sanitizerで確認。public Runtime E2E、対象platform、release supportはこのcloseに含めない。 |
| MF-O03 | power-cut HIL未 | every FULL group boundary |
| MF-O04 | compact RF mapping未 | separate accepted ADR |
| MF-O05 | physical Wi-Fi path HIL未 | Generic Fabric software mappingは実装済み。physical target evidenceは別管理 |
| MF-O06 | independent acceptance review | **CLOSED** — 2026-08-01 fresh independent reviewでexact design **P0=0 / P1=0 / P2=0**。implementation-only abort reason naming P1はdesign acceptanceと分離して修復。 |
| MF-O07 | compatibility matrix | **CLOSED** — private control proposed versionは空、独立`private_mfdt_protocol` version 1 / base control 1・2 bindへ同期。 |
| MF-O08 | platform-rooted promotion authority未実装 | **OPEN / release blocker** — Accepted evidence schemaとtrust anchor、secure-boot由来device/build/profile binding、durable monotonic anti-rollback state、expiry/revocation authorityを先に定義する。その後target-only verifierを実装し、forged provider/magic/non-zero/digest-shaped evidenceのnegative test、rollback/revocation test、pinned ESP target closure、physical power-cut matrixをすべて通す。単なるfunction pointer / weak hook / CI setterはclose条件を満たさない。 |
| MF-O09 | Application-handoff amendment review | **CLOSED / SPEC_ACCEPTED** — 初回NO-GOのP0/P1/P2を修復後、限定re-reviewでadmission profile revision 2、fixed 228-byte binding、sender original/OPEN equality、receiver party/target carrier/OPEN validation、NTS3 1.2 correlation、evidence digest/orderを再確認し **P0=0 / P1=0 / P2=0 GO**。仕様のみのcloseであり、implementation / HIL / releaseは未完。 |

### Reservation expiry (mandatory active free)

When `now_ms >= reservation_not_after_ms` while active and not content-verified
(same predicate as §Abort and expiry; `MF-NEG-EXPIRY-BOUNDARY-EQ` reason
`now_ge_not_after` — residual `now_ms >` wording is **void**):
one durable FULL `G_*_EXPIRY` **must** (1) put canonical NM30
ABORTED terminal-only reason `EXPIRED=5`, abort generation 0, actor zero,
(2) erase active NM3S/NM3R, (3) retain NRC1 until retention GC, (4) set active_count=0.
REJECT EXPIRED alone without this FULL is **forbidden** (would permanently occupy the active slot).
After expiry tombstone, a new transfer_id may be admitted (ESP active max 1 / host max 4).

## 非主張 / Non-claims

本ADRのbaselineと現行Application-handoff amendmentはAccepted / SPEC_ACCEPTEDである。
ただし仕様受入は実装完了を意味しない。次を主張しない:

- `RELEASE_SUPPORTED`またはdefault-ON
- multi-frame implementation complete
- BoundedTransfer public API
- power-cut HIL success
- platform-rooted promotion authorityの実装完了、または「残りは物理HILだけ」
- compact RF direct mapping / physical Wi-Fi multi-frame HIL
- U5/U6 Accepted freezeの変更（変更していない）
- multi-frame production implementation / public ABI / power-cut HIL
- Application handoff / Receipt実装、NTS3 schema 1.2 codec、または改訂OPEN production対応
- OSS / Fabric / PA / Domain / Relay / Multi-parent completion
- （注）CMakeのMFDT 10 tests（generator/Python/Node/C + acceptance の check/self-test）は
  SPEC_ACCEPTED designの検証登録であり、実装完成やrelease supportを意味しない

## Related

- Machine vector: [`spec/vectors/multi-frame-durable-transfer-spec-v1.json`](../../spec/vectors/multi-frame-durable-transfer-spec-v1.json)
- Current amendment work: [`docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md`](../work/2026-08-01-mfdt-application-handoff-spec-repair.md)
- Promotion record: [`docs/work/2026-08-01-mfdt-spec-accepted-promotion.md`](../work/2026-08-01-mfdt-spec-accepted-promotion.md)
- Baseline independent review: [`docs/reviews/2026-08-01-mfdt-spec-accepted-review.md`](../reviews/2026-08-01-mfdt-spec-accepted-review.md)
- Application-handoff amendment independent review: [`docs/reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md`](../reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md)
- Work record: [`docs/work/2026-07-29-multi-frame-durable-transfer-spec-repair.md`](../work/2026-07-29-multi-frame-durable-transfer-spec-repair.md)
- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [U6 Transport Custody](../26-u6-transport-custody.md)
- [ADR-0006](0006-u6-transport-custody.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0017](0017-bearer-registry-path-selection.md)
