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
   ここでいうadmissionはRuntimeの`ninlil_submit()` admissionではなく、Fabricが各attemptを
   初めてdispatchする直前の**Fabric attempt admission**である。現Runtime Platform ABI v1は
   submission時のpath reservation hookを持たないため、`route_feasibility_verified`、
   `bearer_capacity_reserved`、`airtime_reserved`をFabricの存在だけで1にしてはならない。
   Runtime transactionが先にdurable commit済みでも、Fabric attempt admissionが成立しなければ
   bearerは`WOULD_BLOCK`、`UNAVAILABLE`、`DENIED`のexact対応を返し、Runtimeのbounded
   retry/park/terminal contractへ戻す。経路が無いtransactionを成功またはreserved済みにしない。
6. Fabricのportable canonical packetを**Fabric Logical Envelope v1 (`NFL1`)**とする。
   exact field、offset、big-endian、584-byte header、2048-byte codec buffer ceiling、
   1925-byte maximum valid encoded length、1024-byte payload上限、variable field order、CRC32C、
   ownership、failure semanticsは
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

## Runtime ABI v1とのenrichment境界

`ninlil_bearer_message_t`にはauthority binding、path policy、selected pathのfieldがない。
そのC structを変更した、暗黙tailを読んだ、またはpointer外領域をsidecarとみなした実装は禁止する。
Fabricは次の二つのdurable registryとattempt recordからNFL1だけをenrichする。

1. **Path policy registry:** service identity/family/directionから、exact 1個のimmutable
   policy identity/revision/digestを決定する。multi-parent policyはさらにclosed
   `traffic_class`と`scope_endpoint_selector`（`SOURCE_RUNTIME=1`または
   `TARGET_RUNTIME=2`）をcanonical recordへ持つ。selectorが指す
   `source.runtime_id`または`target.target_runtime_id`を`endpoint_runtime_id`とし、
   all-zero、role/policy不一致をrejectする。Device/Installation IDの有無から推測しない。
   0件、複数match、digest conflictはattempt admission失敗とする。
2. **Authority/assignment registry:** concrete target + service scope + directionから、
   ABSENTを明示許可したdirect policy、またはexact 1個のBOUND assignmentを決定する。
   単一owner profileでは少なくとも
   `{authority_id, authority_term, assignment_epoch}`、ADR-0020 multi-parent profileでは
   `owner_scope_id`と同ADRのfull downlink-owner tuple、canonical
   `owner_assignment_digest`をcopy-ownする。NFL1へ載る3-field authority groupはfull tupleの
   代替ではなく、envelopeのsource/target、namespace/service、direction、route policy
   identity/revision/digest、path policy内のtraffic class/scope endpoint selectorと組にした
   **bounded registry lookup key**である。送受信側はこのkeyから同じfull tupleを一意に解決し、
   digest conflict、0件、複数matchをrejectする。

   同じ`owner_scope_id`とauthority termでは、assignment revision、owner controller/cell、
   direction、E2E context/key/security/binding、authority clock/lease、handoff tokenのいずれかが
   変わるたびに`assignment_epoch`をexact +1し、過去値を再利用しない。unchanged tupleの
   idempotent再読だけが同じepochを使える。wrap時はstrictly greater authority termと新しい
   non-zero epochを要する。異なるscopeは独立epochを持てるが、scopeを跨いでtupleを推測・流用
   しない。これにより現ABI v1の3-field groupから同一scope内のold/new full tupleを曖昧に
   解釈しない。暗黙ABSENT、stale/expired/conflicting assignmentはattempt admission失敗とする。

Fabricは最初のsend callで、input `ninlil_bearer_message_t`をcall中だけborrowし、
`{transaction_id, attempt_id}`をkeyに次を1個のcanonical **attempt dispatch record**へ
copy-ownしてからpacket-linkへ渡す。

```text
message canonical digest
path policy identity / revision / digest
authority binding state、NFL1 3-field group、owner scope、full owner tuple/digest
descriptor + security + availability snapshot
selected path ID and selection epoch
encoded NFL1 digest and length
reservation identity / deadline / state
```

同じattemptの`WOULD_BLOCK`/partial transport retryはこのrecordを再利用し、current registryから
policy、authority、security、availabilityを取り直してsilent upgrade/downgradeしない。
snapshotのhard expiry、authority fence、security revocation、compliance denyはrecord再利用より
優先し、TX 0とする。別pathへ再選択する場合は上位Runtimeがnew attempt IDを発行した後だけ
新recordを作る。同じattempt IDで異なるmessage digest、policy、authority、selected pathを
受けた場合はconflictとして送信0にする。

受信側FabricはNFL1検証後、source/target/service/direction/policy recordのtraffic class/
scope endpoint selectorと3-field authority groupからfull owner tupleを一意に解決・検証する。
APPLICATIONまたはCANCEL_REQUEST ingress時に導出した`endpoint_runtime_id`と
`owner_scope_id`を、reverse messageに必要なtrigger contextとして
`{transaction_id, triggering_attempt_id, triggering_kind}`でFULL/canonical保存してからだけ、
NFL1から既存`ninlil_bearer_message_t`へlosslessにprojectしてRuntimeへ公開する。
APPLICATIONより先に届いたCANCEL_REQUESTも独立contextとして保存し、APPLICATION contextを
推測・流用しない。RECEIPT、DISPOSITION、CUSTODY_ACCEPTEDはtriggering APPLICATION context、
CANCEL_RESULTはtriggering CANCEL_REQUEST contextのauthority groupをbit-exact echoし、
それぞれに保存済みendpoint runtime/owner scope/full tupleを使う。
reverse envelopeでsource/targetが反転してもscope endpointを再導出しない。missing/conflicting
context、またはregistry lookupが保存済みdigestと矛盾する場合はreverse送信0とし、current
assignmentから推測しない。APPLICATION受信を成功公開しただけでcustodyやApplication Receiptを
作らない。

Fabric registry/attempt storeとRuntime transaction storeは別atomic domainである。
両者を1 transactionと主張しない。Fabric commitが`COMMIT_UNKNOWN`ならそのattemptを
`LOST_UNKNOWN`としてfenceし、read-classify/reconcile前に再encode・別path sendを行わない。
Runtimeの既存admission assuranceは0のまま正確に保ち、将来submission時のremote/path reservationを
要求する場合は、Platform ABI v1を暗黙変更せず別versioned Runtime extension ADRを要する。

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

### SPEC_ACCEPTED（実装開始を許可する設計gate）

次をすべて満たした時点で本ADRを設計決定としてAcceptedにできる。これはFabric実装済み、
target対応、production supportを意味しない。

1. NFL1 exact KAT（各kindのminimum-valid/zero-optional-fields、全field、最大長）とCRC32C
   cross-language oracle
2. endian/padding/pointer非依存をLP64/ILP32、GCC/Clang、Linux/macOSで証明
3. truncated、trailing、overflow、unknown version/enum/flag、CRC mutationを全reject
4. encode borrow、decode copy-own、buffer-too-small副作用0、clear zeroization
5. public Fabric APIの関数signature、opaque handle/workspace lifecycle、borrow/copy ownership、
   thread/reentrancy、status precedence、packet-link callback contractをexactに固定
6. path policy/authority registry、attempt dispatch/ingress trigger recordのcanonical key/value、
   byte layout、CRC、maximum count、retention、COMMIT_UNKNOWN recoveryをKAT化
7. Runtime admissionとFabric attempt admissionの境界、旧`ninlil_bearer_message_t`からNFL1への
   enrichment、NFL1から旧messageへのlossless projectionを全6 kindで証明
8. deterministic selectionのeligibility、sort/tie-break、reservation、reselection、
   expiry/revocation/compliance precedenceを独立modelで固定
9. Runtime ABI golden manifest不変、既存v1 consumer compile/link、raw struct fallback 0
10. resource profile、compatibility、requirements traceability、独立reviewでP0/P1 0

### RELEASE_SUPPORTED（100%完成を許可するrelease gate）

SPEC_ACCEPTED後の実装について、次をすべて満たす。

1. simulated packet link + Wi-Fi + second Wi-Fiの2種3 instance deterministic host simulation。
   LoRaは別Accepted compact mapping後だけ追加
2. availability/security/authority epoch race、hot unregister、queue exhaustion、deadline、
   no eligible path、policy/assignment conflict
3. same transaction/new attempt failoverとdedupe、same-attempt mutation送信0、false success 0
4. attempt dispatch/ingress trigger全write point crash、COMMIT_UNKNOWN read-classify、
   Runtime/Fabric restart順序の全組合せ
5. Linux/macOSの2 process E2E、10,000 message、24h bounded host soak
6. ESP32-S3でWi-Fi実adapter、target-executed test、強制切断/restart、24h bounded soak
7. Runtime ABI旧consumerと新Fabric consumer、mixed-version/rollback、schema migration
8. public example、porting guide、diagnostics/runbook、release artifact install、
   independent post-CI review

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
