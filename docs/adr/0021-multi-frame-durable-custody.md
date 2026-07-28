# ADR-0021: Multi-frame Durable Transfer and Custody

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-28  
受入日: —（未受入）

## Context

[U6](../26-u6-transport-custody.md)と[ADR-0006](0006-u6-transport-custody.md)はprivate
control protocol v2のsingle-frame custody、dual FULL、COMMIT_UNKNOWNを固定し、
fragmentation/multi-frame resumeを対象外にしている。一方、1024-byte logical packetや
packet-link MTUを超えるBoundedTransferには、bounded chunk、再開、全体digest、
partial apply防止が必要である。

U6 v2 messageを暗黙にmanifest/chunkへ再解釈すると既存peerとのwire互換とcustody証拠を壊す。
またRadio FRAGは[30章](../30-r6-secure-radio-wire.md)のlink/wire mechanismであり、
application-level durable transferと同一ではない。

## Decision

1. U6 v2をsingle-frameのまま変更しない。multi-frame durable transferは
   **private control protocol v3**でnegotiationする別catalog候補とする。
   唯一のcarrierはNCL1 `logical_version=1` over NCG1 `DATA (0x03)`とする。
   NFL1/NWB1 application packetへcontrol/custody messageを載せない。
   NRW1 `wire_profile_id=0x11`は変更しない。
2. v3はTransfer Open、paged Manifest、Chunk Offer/Accept、Resume Query/State、
   Transfer Accept/Reject/Busy、Abort/Ackを持つ。candidate exact message type、byte layout、
   hash domainは本ADRの§「Control protocol v3 candidate exact profile」で固定する。
   `SPEC_ACCEPTED`まではreserved候補であり、v2 closed catalogへsilent追加しない。
3. manifestはtransfer_id、origin transaction/event identity、manifest revision、
   total logical length、chunk count、chunk size/offset/digest一覧、whole-content digest、
   application schema/service identityをcanonicalにbindする。同一transfer_idで異なるmanifestを拒否する。
   digest listは`MAX_NCL1_BODY=998`を超え得るため、bounded paged manifestを必須とする。
   page index/count、entry index/count、per-page entry上限、chunk count/size、total size、page digest、
   complete-manifest digestをexact v3 freezeで固定する。単一bodyへ収まると推測しない。
4. chunkはmanifestで宣言されたexact offset/length/digestと一致しなければならない。
   overlap、gap、範囲外、count/length overflow、digest conflictをfail-closedにする。
5. receiverはmanifestとfinite capacity reservationをFULL commitした後だけchunkを受ける。
   chunk bytesとreceived bitmap/digest evidenceをFULL commitした後だけChunk Acceptを送る。
6. senderはChunk Accept受領記録をFULL commitした後、そのchunkの再送用copyを解放できる。
   ただしmanifest、whole digest、transaction evidenceはfinal Transfer Acceptがsender側FULLに
   なるまで保持する。
7. receiverは全chunk FULL、manifest一致、whole-content digest一致を確認し、reassembled objectと
   Transfer Accept intentをFULL commitした後だけTransfer Acceptを送る。
   senderはTransfer AcceptをFULL commitした後だけcustody transfer completeとする。
8. partial chunk、RAM reassembly、socket write、Radio FRAG_ACK、NWB1 successを
   Application Receipt、transfer complete、application visibilityにしない。
   application handoffへは検証済みreassembled objectとstable publication tokenだけを渡す。
   crashを跨ぐcallback exactly-onceを単独Runtimeから主張せず、同じtokenの再提示とupper durable
   evidenceによるeffect dedupeで閉じる。
9. reconnect/resumeはfresh authenticated session上でtransfer_id + manifest digestを提示し、
   receiverのFULL committed bitmapだけを根拠にする。sender/receiverの証拠が矛盾する場合は
   COMMIT_UNKNOWN recoveryを行い、offsetを推測しない。
10. v3 logical record kinds/keyspaceは既存control namespace exact `ninlil.ctl.v1`内へ置く。
    manifest pages、chunk map/records、whole digest、receiver/sender acceptance、application
    publication fenceを新4-byte kind prefixでkey-space分離する。別physical namespaceを作らず、
    ESP namespace hard max 4 / production default 2と、U5/U6/v3合計control keys hard max 32、
    RW txn≤1/RO txn≤1/iter≤1を維持する。exact kind IDs/key/value layout/count予算はv3 freezeで
    固定し、U6 v2 recordをin-place拡張・再解釈しない。
11. total bytes、chunk bytes/count、concurrent transfers、per-peer reservations、resume attempts、
    tombstones、retention、digest workをprofileでboundedにする。capacity予約できない場合は
    manifest受理前にBUSY/REJECTし、途中chunkをevictしてsuccessを維持しない。
12. 本ADRをAcceptedにする前に[06章](../06-versioning-and-compatibility.md)、
    [23章](../23-usb-radio-boundary.md)、[25章](../25-u5-cell-operating-assignment.md)、
    [26章](../26-u6-transport-custody.md)を同一changeで更新し、control v3 negotiation/catalog、
    NCL1/NCG1 carrier、`ninlil.ctl.v1`新kinds/budgetをre-freezeする。

## Control protocol v3 candidate exact profile

### Version negotiation and catalog inheritance

NCL1 envelope `logical_version=1`、26-byte header、998-byte body上限、NCG1 `DATA (0x03)`を
変更しない。HELLO/HELLO_ACK bodyも8 bytesのまま、flags/reservedは0を維持する。
v3-capable endpointは`min_control_version`と`max_control_version`を`1..3`のclosed rangeで送り、
両者のintersectionの最大値を選ぶ。control version 3は別capability bitを要さず、
**selected exact 3そのもの**がmulti-frame supportを表す。これによりflags非0を拒否するv1/v2
peerとのHELLO互換を壊さない。

selected versionごとのclosed catalogは次とする。

| selected control version | 受理するcatalog |
| ---: | --- |
| 1 | U4 HELLO/PING/PONG/RESETだけ |
| 2 | version 1 catalog + U5 assignment + U6 single-frame custody |
| 3 | version 2 catalogをbit-exact維持 + 本ADR v3 multi-frame catalog |

`selected==3`でU5/U6 v2 messageを使うことはsilent `>=2`解釈ではなく、このversion 3 catalogが
明示的に継承する規則である。v1/v2実装はv3 messageをunknownとしてrejectする。転送途中の
selected version変更、v3 recordのv2 OFFER化、v2 transferのv3 in-place昇格は禁止する。

### Fixed limits

| Item | Exact candidate |
| --- | ---: |
| maximum logical content | 32768 bytes |
| normal chunk size | 896 bytes |
| maximum chunk count | 37 |
| manifest entry size | 40 bytes |
| entries per manifest page | 22 |
| maximum manifest pages | 2 |
| maximum active v3 transfer / ESP control namespace | 1 |
| maximum active v3 transfer / Host reference profile | 4 |
| maximum resume queries / transfer / session generation | 8 |
| receiver reservation lifetime | 300000 ms, immutable trusted local platform monotonic epoch |
| completed/tombstone retention | 86400000 ms or explicit upper handoff policy, whichever is longer |

For `total_length > 0`,
`chunk_count = ceil(total_length / 896)`、chunk `i`のoffsetは`896 * i`、lengthは
`min(896, total_length - offset)`で一意に導出する。non-final chunk lengthはexact 896である。
`total_length=0`ではchunk/page countとも0、content digestはSHA-256(empty)である。
`manifest_page_count = ceil(chunk_count / 22)`で、0..2以外を拒否する。
加減算、ceil、offset計算はchecked integerで行い、overflow時はdecode/admissionを変更せずrejectする。

### Message type allocation

次の値は`SPEC_ACCEPTED`でreservedとなるcandidateである。全messageはactive sessionの
generation/cookie exact一致、requestはnon-zero request ID、responseはrequest IDをechoし、
NCG1 `DATA`だけに載せる。

| message | type | direction / correlation |
| --- | ---: | --- |
| `TRANSFER_OPEN` | `0x40` | sender → receiver request |
| `TRANSFER_OPEN_ACCEPT` | `0x41` | receiver → sender response |
| `MANIFEST_PAGE` | `0x42` | sender → receiver request |
| `MANIFEST_PAGE_ACCEPT` | `0x43` | receiver → sender response |
| `TRANSFER_REJECT` | `0x44` | receiver/peer → requester response |
| `TRANSFER_BUSY` | `0x45` | receiver → requester response |
| `CHUNK_OFFER` | `0x46` | sender → receiver request |
| `CHUNK_ACCEPT` | `0x47` | receiver → sender response |
| `RESUME_QUERY` | `0x48` | sender → receiver request |
| `RESUME_STATE` | `0x49` | receiver → sender response |
| `TRANSFER_FINALIZE` | `0x4a` | sender → receiver request |
| `TRANSFER_ACCEPT` | `0x4b` | receiver → sender response/final evidence |
| `TRANSFER_ABORT` | `0x4c` | current responsibility owner → peer request |
| `TRANSFER_ABORT_ACK` | `0x4d` | peer → owner response |

0x40..0x4dのunknown/reserved body、wrong direction/type binding、selected version !=3は業務解釈せず
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

timeout retryは同じsemantic bodyと新しいnon-zero request IDを使う。receiverは**current durable
state**から新しいsuccess responseを再構成する。OPEN/CHUNK/FINAL/ABORTのimmutable bind/evidenceは
bit-exact維持する。PAGE_ACCEPTのreceived count/completeとRESUME_STATEのrecord generation/
bitmap/stateは、その間にFULL進行したcurrent値へ単調に進んでよく、過去snapshotへ戻さない。
senderは同じmanifest bind内で新しいcurrent responseをmergeし、count/bitmap/generation後退や
同generation conflictをrejectする。1 request IDへ2 responseを返さず、response受理後のlate
duplicateはstateを変えない。valid BINDまでdecodeできないlayout errorはsemantic REJECTを
捏造せず、CTRL_ERRORまたはdrop/counterとする。

### Canonical manifest

全multi-byte integerはunsigned big-endian、全reserved/flagsは0である。namespaceは
`[a-z0-9][a-z0-9.-]*`、service/schemaは`[a-z0-9][a-z0-9._-]*`のASCIIで各1..63 bytesとし、
Foundation `ninlil_text_id_t`へbit-exact projectする。UTF-8一般やNULを許可しない。IDは16-byte all-zero禁止、
digest algorithmはSHA-256 exact `0x0001`、digestはall-zero禁止である。

`TRANSFER_OPEN` bodyはfixed 234 bytes + 3 text fieldsで、最大423 bytesである。

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
234     N      namespace || service || schema
```

deadline epochとabsolute deadlineは両方zeroのNO_DEADLINE、または両方non-zeroだけを許す。
`manifest_digest = SHA-256("NM3-MANIFEST-V1" || open bytes [0,202) ||
open variable text bytes || manifest_entry[0] || ... || manifest_entry[chunk_count-1])`とする。
ASCII domainは終端NULを含めない。digest field自身、request/session fields、page header/page digestは
inputに含めない。同じtransfer IDでrevision/digest/open bytesの1 byteでも違えば
`DUPLICATE_CONFLICT`であり、higher revisionによるin-place置換はしない。新しい内容は新transfer IDを
要する。

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
epochをreservation epochとし、checked `now_ms + 300000`をimmutable expiryにする。
OPEN effect deadlineは同epochへAccepted deadline-projection recordがある場合だけearlier boundへ
短縮する。NO_DEADLINEまたは異epochを数値比較しない。deadlineが既にexpired、projectionが必要だが
不能、clock epochが途中で変化した場合はreservation/publishをfenceし、expiryを別epochへ延長しない。
`manifest_complete`はzero-length OPENでexact 1、それ以外はOPEN_ACCEPT時0である。

各MANIFEST_PAGEはFULL後に同じpage index/digestを持つPAGE_ACCEPTを1件返す。
`manifest_complete=1`は全page bitmap、entry、page digest、whole manifest digest検証後にだけ
許す。初回は最後の不足page responseで0→1になる。完了後の任意duplicate page retryにはcurrent
complete=1とcurrent received countを返してよく、元の0 responseを再現しない。2-page時の先行pageへ
初回はcomplete=0 responseを返す。zero-pageではOPEN_ACCEPTのcomplete=1が同じ意味を持つ。

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
| 4 | unsupported version/profile |
| 5 | capacity/reservation |
| 6 | storage definite failure |
| 7 | expired/deadline |
| 8 | state/order |
| 9 | authority/identity/service mismatch |
| 10 | abort denied because peer already transferred responsibility |

busyはcapacityが一時的でdurable stateを変更しなかった場合だけ。COMMIT_UNKNOWN、
corrupt、identity conflict、deadline terminalをBUSYへ変換しない。unknown status/stageをrejectする。

abort reasonは`OPERATOR=1, SUPERSEDED=2, DEADLINE=3, POLICY=4`だけで、0/unknownをrejectする。
resume query generationは1から開始し、新しいqueryはprevious +1 exact、最大8である。同generation/
same bodyのretryだけをidempotentとし、gap/rollback/same-generation conflictをrejectする。

## State, custody and recovery

SenderはOPEN/content/manifest/chunk bytesをFULL保持してからOPENを送る。receiverはOPENの全上限を
検査し、content byte数、1 active slot、control namespace byte/key budgetを**先に予約してFULL**
した後だけOPEN_ACCEPTを返す。全manifest pageをFULLしmanifest digestを再計算した後だけ
最後のMANIFEST_PAGE_ACCEPTを`manifest_complete=1`で返す。各chunkはpayload、bitmap、
record generationを同じFULL recordへcommit後だけ
CHUNK_ACCEPTを返す。

全chunk FULL後、receiverはcanonical順でwhole digestを検証し、`content_complete=1`、
application publication `READY` token、receiver evidence ID/record digestを同一FULLへ入れる。
matching FINALIZEを受けた後だけTRANSFER_ACCEPTを送る。
senderはmatching TRANSFER_ACCEPTとacceptance record digestをFULL記録した後だけ
release policyを実行できる。CHUNK_ACCEPT/bitmap/RESUME_STATEだけでsender contentを解放しない。

publication tokenは
`SHA-256("NM3-PUBLISH-V1" || BIND52 || whole_content_sha256 ||
total_length_u32_be || receiver_evidence_id)[0..15]`で、all-zeroならinternal failureとして
READY/TRANSFER_ACCEPTを0にする。upper handoffは
`prepare(publication_token, verified whole object)`を受け、同tokenをdurable dedupe keyにする。
crash/restartでREADYならRuntimeは同じtokenを再提示できる。upperがeffect/ownershipをFULLした
evidence digestを返した後、Runtimeはtoken + evidence digest + `PUBLISHED/HANDOFF_COMPLETE`を
同一FULLにする。callback回数exactly-oneは主張せず、**application effect**はstable tokenに対する
upper `PREPARED/ALREADY_COMMITTED` contractで最大1回にする。このcontractを実装しないapplicationは
automatic effectを行わず、verified objectのmanual pullだけを使う。

receiver responsibilityはupper handoff FULLまたはauthority actorによるABORT FULLだけで終了する。
receiverがcontent complete済み、または上位へ公開済みならsender起点ABORTを拒否する。
abort generationは同transferで1から開始し、同じreason/actorのretryは同generation、
新semantic abortはprevious +1 exact、最大8、wrap/gap/rollbackをrejectする。
abortのowner、reason、generation、manifest bindをactive recordとtombstoneへFULLした後だけACKする。

各FULLがCOMMIT_UNKNOWNならwire success/acceptを0にし、同じkeyをread-classifyする。expected
full bytesとbit-exact一致ならHost proven storeだけが対応stateへ進める。old exactならretry、
partial/mixed/unknown schemaならCORRUPT fenceする。ESP format-4はpower-cut HILでFULL promotionが
証明されるまでreadback一致をsuccessへ昇格しない。reconnect時はfresh authenticated sessionの
RESUME_QUERYだけを使い、receiver durable bitmap以外からoffsetを推測しない。

## Durable storage candidate

既存`ninlil.ctl.v1`へ次の3 kindを追加する。keyはいずれも20 bytes
`kind[4] || transfer_id[16]`である。

| kind | owner | value |
| --- | --- | --- |
| `NM3S` | sender active/evidence | canonical sender record v1 |
| `NM3R` | receiver reservation/manifest/chunks/publication | canonical receiver record v1 |
| `NM30` | completed/aborted/corrupt terminal tombstone | canonical terminal record v1 |

ESP profileは同時active v3 transferをdirection合計1とし、active recordは1 key、terminal transitionで
active delete + NM30 putを同一FULLにするため2 keysを予約する。ARW最大4、U6 v2、v3を合わせて
namespace 32 keys/69632 logical bytesを超えるadmissionはstate mutation 0でBUSY/REJECTする。
v3用に2 staging key slotsと40000 logical bytesを予約できない場合はOPENを受けない。
U6 v2の8 transfer IDは上限であり、v3 reservationを横取りする保証ではない。

NM3S/NM3Rは単一canonical valueにheader、exact TRANSFER_OPEN body、全manifest entry、
bitmap、content bytesを保持する。missing pageのentry領域と未受信chunkのcontent領域はcanonical
zeroで、page/chunk bitmapだけがpresent authorityである。zero-filled実chunkとはbitmapで区別する。
headerは308 bytes exact:

```text
offset  bytes  field
0       4      magic = key kind ("NM3S" or "NM3R")
4       2      schema = 1
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
84      2      open_body_length, 237..423
86      2      manifest_entries_length = 40 * chunk_count
88      4      content_length = OPEN total_length
92      2      chunk_count
94      2      manifest_page_count
96      8      chunk_progress_bitmap
104     1      manifest_page_bitmap; bits >= page_count zero
105     1      retry_budget_remaining, 0..8
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
300     4      reserved2 = 0
304     4      header_crc32c over bytes [0,304)
308     O      exact TRANSFER_OPEN body
308+O   E      manifest entry slots, E=40*chunk_count
308+O+E L      content slots, L=content_length
308+O+E+L 4    record_crc32c over all preceding record bytes
```

OPENの3 textが各1 byte以上なのでminimum open bodyは`234+3=237`である。
maximum exact NM3S/NM3R valueは
`308 + 423 + 37*40 + 32768 + 4 = 34983` bytesで、single value 65536以下である。
headerのtransfer/revision/manifest/content/chunk/page fieldはembedded OPENとbit-exact一致し、
OPEN bodyのderived count/digest検査も毎readで繰り返す。variable offsetは上式からchecked導出し、
gap、overlap、short、trailing、CRC不一致をCORRUPTとしてwire success 0にする。

state codeはsideごとのclosed setである。

| side | code | state / mandatory invariant |
| --- | ---: | --- |
| sender | 1 | `S_OPEN_PENDING`: content/全entry present、progress=0、reservation/evidence zero |
| sender | 2 | `S_OPEN_ACCEPTED`: reservation non-zero、manifest page send可 |
| sender | 3 | `S_MANIFEST_ACCEPTED`: page bitmap all-set、chunk send可 |
| sender | 4 | `S_CHUNKS_PARTIAL`: progressはFULL保存済みCHUNK_ACCEPTだけ |
| sender | 5 | `S_FINAL_WAIT`: progress bits 0..chunk_count-1 all-set |
| sender | 6 | `S_ACCEPT_RX`: receiver evidence/digest/generation non-zero、payloadはrelease policyまで保持 |
| sender | 7 | `S_TERMINAL_COMPLETE`: evidence FULL、payload release policy適用済み |
| sender | 8 | `S_ABORT_PENDING`: responsibility未移転、abort generation/reason/actor FULL |
| sender | 9 | `S_TERMINAL_ABORTED`: matching ABORT_ACK/tombstone FULL |
| sender | 10 | `S_COMMIT_UNKNOWN`: wire success 0、read-classifyだけ |
| receiver | 32 | `R_RESERVED_OPEN`: reservation FULL、page/chunk bitmap 0 |
| receiver | 33 | `R_MANIFEST_PARTIAL`: page bitmap non-zeroだがnot all |
| receiver | 34 | `R_MANIFEST_ACCEPTED`: all pages/digest verified、chunk受理可 |
| receiver | 35 | `R_CHUNKS_PARTIAL`: chunk progress not all |
| receiver | 36 | `R_CONTENT_VERIFIED`: all bits、whole digest、publication token READY、acceptance evidence/generation non-zero |
| receiver | 37 | `R_ACCEPT_NOTIFIED`: accept_notified=1、responsibility保持 |
| receiver | 38 | `R_HANDED_OFF`: handoff COMPLETE、retention後terminal化可 |
| receiver | 39 | `R_ABORTED`: authority abort FULL、publication NONE |
| receiver | 40 | `R_COMMIT_UNKNOWN`: wire success 0、read-classifyだけ |

stateと矛盾するbitmap、reservation、publication、handoff、accept/evidence fieldはCORRUPTである。
sender progress bitmapはmatching CHUNK_ACCEPTのsender側FULL evidence、receiver progress bitmapは
chunk bytesのreceiver側FULLだけを表す。同じbitをraw wire観測だけで立てない。

NM30 valueは164 bytes exact:

```text
0/4 magic="NM30"; 4/2 schema=1; 6/2 value_length=164;
8/16 transfer_id; 24/4 manifest_revision; 28/32 manifest_digest;
60/2 terminal_state; 62/2 terminal_reason; 64/4 abort_generation;
68/16 receiver_evidence_id; 84/32 acceptance_record_digest;
116/16 authority_actor_id; 132/16 retention_anchor_clock_epoch_id;
148/8 retention_anchor_mono_ms; 156/4 reserved=0;
160/4 crc32c over [0,160)
```

terminal stateは`COMPLETE=1, ABORTED=2, CORRUPT_FENCED=3`だけ。COMPLETEはreceiver evidence/
acceptance digest non-zeroかつterminal reason/abort generation/actor zero、ABORTEDはreason 1..4、
abort generation 1..8、actor non-zero、CORRUPT_FENCEDはterminal reason `0x8001`かつautomatic
payload releaseを禁止する。active→terminalは同一FULL final viewでactive keyをeraseしNM30をputする。
COMMIT_UNKNOWNはactive-oldまたはNM30-newをfull compareし、両方/missing/partialをCORRUPT fenceする。

namespace scannerはkey length 20の`NM3S/NM3R/NM30`をknown kindへ追加し、wrong key length、
magic/key mismatch、unknown schemaをforeign/corruptとして隔離する。U5/U6 v2 recordを
再解釈しない。

最大active row logical bytesは`16 + key20 + value34983 = 35019`、terminal rowは
`16 + 20 + 164 = 200`。v3 admissionはcommitted 1 key/35019 bytesと、terminal transitionの
staging union用追加1 key/200 bytes、合計2 entry/35219 bytesを予約する。ARW/U6/current namespace
viewを加えたfinalが32 keys/69632 bytes、begin+final unionが64 entries/139264 bytes以下であることを
storage transaction開始前に検査する。active maximum replacementのbegin+final logical bytesは
`35019 * 2 = 70038`で139264以下である。境界exact、+1はstate mutation 0でCAPACITY rejectする。

format-4はFULL commitごとにcheckpointを行うため、ESP reference profileはv3によるFULLを
80/day以下、最大32768-byte transferを2/day以下に制限する。超過は新OPENをrejectし、
既存custodyをevictしない。Host profileはSQLite FULL契約と別quotaを使い、ESP値を暗黙流用しない。

## Radio fragmentationとの境界

- Radio FRAGは1個のradio semantic messageを[30章](../30-r6-secure-radio-wire.md)どおり
  2〜13 fragmentへ分けるlink-layer reliabilityである。
- v3 chunkはdurable transferのstorage/custody単位であり、1 chunkがさらにRadio FRAGへ
  写像される場合がある。
- Radio FRAG_ACKはchunk durable commitを意味せず、Chunk AcceptはRF airtime permitを意味しない。
- Radio FRAG timer/resourceを変更せず、変更が必要なら新wire profile IDを割り当てる。

## Compatibilityとmigration

- selected control version exact 3だけをmulti-frame critical capabilityとし、別flagを要求しない。
- 非対応peerにはU6 v2 single-frameだけを提示し、926-byte上限を超える場合は明示拒否する。
- v3からv2へtransfer途中でdowngradeしない。
- v2/v3 recordは同じ`ninlil.ctl.v1`内でlogical kind/key-spaceを分離し、Radio FRAG stateは
  control custody recordとして混入させない。
- rolling update中は既存v2 transferをv2で完了/期限終了し、v3へin-place変換しない。
- irreversible schema migration後のold binary openは明示拒否する。

## Dependencies

M1a restart-safe kernel、M3 FULL storage、U6 v2 single-frame conformance、
bounded transfer logical APIを前提とする。Radio経路で使う場合はNRW1 FRAG実装も必要だが、
POSIX/Wi-Fi v3 modelとstorage crash matrixは並行実装できる。

## Acceptance

1. minimum-valid/zero-optional-fields/max paged manifest、page/count/size/offset、
   whole/page/chunk digestのcross-language KAT
2. reorder、duplicate、loss、overlap、gap、conflict、truncation、resource exhaustion
3. manifest、各chunk、bitmap、reassembly、Acceptの全write point crash injection
4. COMMIT_UNKNOWNのsender/receiver両truth、reconnect/resume、evidence conflict
5. partial apply 0、duplicate application effect 0、false custody 0。同一publication tokenの
   `prepare`再提示は許可し、upperが`ALREADY_COMMITTED`を返して追加effect 0であること
6. exact v3 IDs/layout/count/size/paging、U6 v2 peerとのmixed-version拒否、
   v2 regression byte/hash不変
7. POSIX 2-process、Wi-Fi/USB実transport、process restart、24h soak
8. ESP power-cut HILで各commit boundary、storage pressure/wear report
9. Radio利用時のFRAG loss/reorderとchunk custodyの独立oracle
10. `ninlil.ctl.v1`内U5/U6/v3合計≤32 keys、namespace default 2/hard max 4、NO_SPACE
11. docs/06/23/25/26同時re-freeze、public BoundedTransfer example、migration/runbook、
    independent review

## Consequences

長いdataを再開可能かつpartial applyなしで運べる。代わりにcontrol v3、manifest/chunk storage、
二重のfragmentation境界、power-cut matrixが必要になる。U6 v2の単純さと互換性は維持される。

## Rejected alternatives

- U6 v2 OFFERを暗黙にmanifestへ再利用する
- RAM reassembly後すぐTransfer Acceptを返す
- Radio FRAG_ACKをdurable chunk custodyとみなす
- receiver bitmapなしに最後に見たoffsetから再開する
- storage不足時に古いchunkをsilent evictionする

## 非主張

本ADRはProposed docs-onlyであり、control v3採番、exact wire freeze、multi-frame implementation、
resume、BoundedTransfer public API、power-cut HIL、production supportを主張しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [U6 Transport Custody](../26-u6-transport-custody.md)
- [ADR-0006](0006-u6-transport-custody.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0017](0017-bearer-registry-path-selection.md)
