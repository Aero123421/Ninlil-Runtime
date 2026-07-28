# ADR-0017: Fabric Bearer Registry and Path Selection

状態: **Proposed — docs-only（implementation / acceptance pending）**  
提案日: 2026-07-28  
受入日: —（未受入）

## Context

Runtimeの公開Platform ABIは1個の`ninlil_bearer_ops_t`を受け取る。これを単純に配列化すると、
既存ABI、ownership、lifecycle、availability semanticsを同時に壊す。一方、LoRa、Wi-Fi、
USB、複数radio/parentを扱うには、複数packet link、path policy、per-path metrics、
bounded schedulingが必要である。

現POSIX loopback wireは`ninlil_bearer_message_t`のraw `sizeof` bytes、pointer、padding、
host endianを直列化する。これは同一build内LAB fixtureであり、portable canonical wireではない。
この形式をWi-Fi/USBや別architectureへ昇格すると、ABI差、pointer leakage、padding、
endiannessに依存する。

## Decision

1. `platform.h`の単一Bearer ABIと`NINLIL_ABI_VERSION=0x0001`を維持する。既存Bearer fieldを
   配列化せず、offset/meaningを変更しない。
2. 新しい公開・portableな**Fabric Bearer**を1個のlogical bearerとしてRuntimeへ渡す。
   Fabric内部のbounded registryが0個以上のpacket-link instanceを所有する。
3. packet-link instanceはopaque 128-bit identity、kind、direction、maximum packet/transfer、
   latency/cost class、sleep compatibility、unicast/broadcast、reservation、regulatory binding、
   availability epochを持つ。同一kindの複数instanceを許す。descriptorはさらにimmutable
   `security_profile_id`、authenticated peer runtime + Attachment binding digest/authority、
   integrity、confidentiality、replay protection、session freshness、custody、evidence capabilityを
   明示する。
4. registry、path list、configuration、per-link/path metricsは独立したversioned opaque
   Fabric APIで公開する。Runtime Platform ABIへ追加配列を埋め込まない。
5. availability snapshotはdescriptor digest、security attestation state/digest/epoch、
   authenticated peer runtime、Attachment authority/bindingを含む。service/traffic classの
   path policyはimmutable identity + revision + canonical digestを持ち、admission時に
   descriptor/security/availabilityと一緒にcopy-own snapshotする。未知、期限切れ、未attest、
   要求するsecurity/custody/evidence capabilityを欠くlinkはineligibleとする。
   attemptごとにselected path、selection epoch、route flagsを記録する。path変更は同じ
   transaction identityと新しいattempt identityで追跡する。
6. Fabricのportable canonical packetを**Fabric Logical Envelope v1 (`NFL1`)**とする。
   exact field、offset、big-endian、584-byte header、2048-byte packet上限、1024-byte payload上限、
   variable field order、CRC32C、ownership、failure semanticsは
   [34章 §5.1](../34-v2-runtime-fabric-completion.md)をNormative candidateとする。
   `authority_id/authority_term/assignment_epoch`はclosed authority-binding groupとして、
   すべてzeroのABSENTまたはすべてnon-zeroのBOUNDだけを許可する。BOUNDは
   assignment/owner-governedまたはpolicy-required flowで必須、ABSENTは明示的に許可された
   controllerless/local/direct flowだけに許可する。reverse kindはtriggering attemptのgroupを
   bit-exact echoし、owner failoverは同一transactionのnew attemptにnew BOUND groupを使う。
   exact規則と6-kind required/zero matrixは34章§5.2を正本候補とする。
7. raw `ninlil_bearer_message_t`、native pointer、padding、native endianをprocess/compiler/
   architecture/transport境界へ送ってはならない。現POSIX raw形式はV1 LAB fixtureとして隔離し、
   NFL1実装後にportable loopbackをNFL1へ移行する。
8. Wi-Fi/USB reliable byte-streamはNFL1をtransport packet化する。compact radio用logical
   envelopeと完全なNFL1↔NRW1 mappingは未定義である。別のNormative byte layout、
   全6-kind双方向mapping、lossless/unsupported規則、KATがAcceptedになるまでLoRa adapterの
   NFL1 send/receiveを禁止する。full NFL1 bytesをNRW1 payloadへ運ぶ方式をdefaultにせず、
   NRW1 byte/profileを変更しない。
9. selectionはdeterministicで、policy eligibility、deadline、availability epoch、reservation、
   compliance、priority、stable tie-breakの順をexact test fixtureで固定する。costだけで
   security/evidence/complianceをdowngradeしない。
10. selected link消失時は送信成功へ変換しない。別linkがsnapshot policy、deadline、
    resource reservationを満たす場合だけ新attemptで再選択する。`LOST_UNKNOWN`は上位transactionの
    retry/dedupe contractへ渡す。
11. packet-link queue、registry、path candidate、metrics、retry、inflight bytesをprofileで
    boundedにする。上限超過時にheap成長や既存予約の横取りを行わない。
12. physical RFはFabric選択後も既存TxPermit/compliance sole authorityを必ず通る。
    Fabric statusやlink availabilityを送信許可として扱わない。
13. NFL1の1024-byte logical packetとU6 v2の926-byte single-frame上限を混同しない。
    packet-link MTUを超える場合は、そのlink固有のversioned fragmentationへ写像するか拒否する。
    1024 bytesを超えるBoundedTransferは新NFL versionまたはADR-0021のstream/chunk mappingを要する。

## Fabric API versionとABI互換

- Runtime Platform ABI: `0x0001`不変
- Fabric API: version 1候補。Accepted前は採番確定・support claimを行わない
- NFL1: logical envelope version 1候補。Ninlil public application data wireではない
- registry storage: schema 1候補。既存Foundation schema 1、ESP physical format 4は不変

Fabric APIはopaque handleと`abi_version + struct_size`を持つ新headerに置く候補とする。
既存`ninlil_platform_ops_t`利用者はFabricを使用せず従来Bearerを渡せる。Fabric利用者は
Fabricが公開する1個の`ninlil_bearer_ops_t` adapterを既存slotへ渡す。

legacy packet-linkにdescriptorがない場合、不明能力を推測せずunsupportedとする。
NFL1非対応peerとのmixed versionでは、明示的にLAB legacy profileを選んだ試験以外はattach拒否する。
silent raw-struct fallbackは禁止する。

## Storageとrecovery

registry recordはinstance identity、descriptor digest、configuration revision、
security profile/binding digest/attestation epoch、availability epochだけをdurableに保持する。
socket handle、pointer、OS fd、volatile metricは保存しない。
path policy recordとattempt selection evidenceは別key spaceに置く。

open/recovery時は次を満たす。

- unknown schema、digest conflict、duplicate instance identityをfail-closed
- active attemptが参照するpolicy revisionを削除しない
- availability epochをrestart前へ巻き戻さない
- COMMIT_UNKNOWN時はold/new両候補を列挙し、証拠なしにselection成功を作らない
- migrationはsource/target marker付きで各write point crash-safe

## Acceptance

Acceptedには最低限次を要求する。

1. NFL1 exact KAT（各kindのminimum-valid/zero-optional-fields、全field、最大長）とCRC32C
   cross-language oracle
2. endian/padding/pointer非依存をLP64/ILP32、GCC/Clang、Linux/macOSで証明
3. truncated、trailing、overflow、unknown version/enum/flag、CRC mutationを全reject
4. encode borrow、decode copy-own、buffer-too-small副作用0、clear zeroization
5. simulated packet link + Wi-Fi + second Wi-Fiの2種3 instance deterministic host simulation。
   LoRaは別Accepted compact mapping後だけ追加
6. availability epoch race、hot unregister、queue exhaustion、deadline、no eligible path
7. same transaction/new attempt failoverとdedupe、false success 0
8. Runtime ABI golden manifest不変と既存v1 consumer compile/link
9. ESP32-S3でLoRa+Wi-Fi同時adapter、target-executed test、24h bounded soak
10. requirements traceability、public example、porting guide、independent review

## Consequences

- Runtime transaction Coreを複数物理transportの詳細から隔離できる。
- 個別application語彙をCoreへ入れず、service policyでpathを選択できる。
- 単一Bearer ABI互換は維持されるが、Fabric自身には新しい公開API、storage、test surfaceが増える。
- compact radio logical envelopeとNFL1↔NRW1 mappingの別仕様・KATが必要になる。

## Rejected alternatives

- **`platform.h`のBearer配列化:** 既存ABIとlifecycle contractを破壊する。
- **Runtime内部へWi-Fi/LoRa分岐を直書き:** portable Coreへport/policy詳細が混入する。
- **raw C structをcanonical wire化:** pointer、padding、ABI、endian依存でportableではない。
- **NFL1 bytesをそのままNRW1へ格納:** radio airtimeと[30章](../30-r6-secure-radio-wire.md) profileを壊す。
- **availabilityだけで自動fallback:** deadline、custody、compliance downgradeを隠す。

## 非主張

本ADRはProposed docs-onlyであり、Fabric API/NFL1採番、実装、POSIX移行、Wi-Fi、LoRa mapping、
Relay、Multi-parent、HIL、legal、production supportを主張しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [Architecture §Bearer](../01-architecture.md)
- [Versioning and Compatibility](../06-versioning-and-compatibility.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0018: Wi-Fi Bearer](0018-wifi-bearer.md)
