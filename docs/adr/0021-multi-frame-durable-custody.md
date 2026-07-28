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
2. v3は少なくともTransfer Manifest、Chunk Offer、Chunk Accept、Resume Query/State、
   Transfer Accept/Reject/Busyを持つ。exact message type、byte layout、hash pinは後続Normative
   byte specと独立KATでfreezeし、v2 closed catalogへsilent追加しない。
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
   application callbackへは検証済みreassembled objectをatomicに1回だけ公開する。
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

## Radio fragmentationとの境界

- Radio FRAGは1個のradio semantic messageを[30章](../30-r6-secure-radio-wire.md)どおり
  2〜13 fragmentへ分けるlink-layer reliabilityである。
- v3 chunkはdurable transferのstorage/custody単位であり、1 chunkがさらにRadio FRAGへ
  写像される場合がある。
- Radio FRAG_ACKはchunk durable commitを意味せず、Chunk AcceptはRF airtime permitを意味しない。
- Radio FRAG timer/resourceを変更せず、変更が必要なら新wire profile IDを割り当てる。

## Compatibilityとmigration

- capability negotiationでcontrol v3とmulti-frame critical capabilityの双方が一致したpeerだけが使う。
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
5. partial apply 0、duplicate callback/effect 0、false custody 0
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
