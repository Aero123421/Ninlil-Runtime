# ADR-0017: Fabric Bearer Registry and Path Selection

状態: **SPEC_ACCEPTED (design only) — private reference candidate implemented; software acceptance pending**  
提案日: 2026-07-28  
設計受入日: 2026-07-29

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
2. 新しいportableな**Fabric Bearer**を1個のlogical bearerとしてRuntimeへ渡す。
   Fabric内部のbounded registryが0個以上のpacket-link instanceを所有する。ADR受入時点の
   APIはprivate / source-only / default-OFF候補であり、installed public ABIへの昇格は
   別の互換性reviewを要する。
3. packet-link instanceはopaque 128-bit identity、kind、direction、maximum packet/transfer、
   latency/cost class、sleep compatibility、unicast/broadcast、reservation、regulatory binding、
   availability epochを持つ。同一kindの複数instanceを許す。descriptorはさらにimmutable
   `security_profile_id`、authenticated peer runtime + Attachment binding digest/authority、
   integrity、confidentiality、replay protection、session freshness、custody、evidence capabilityを
   明示する。
4. registry、path list、configuration、per-link/path metricsはRuntime Platform ABIと独立した
   versioned opaque private Fabric APIで扱う。Runtime Platform ABIへ追加配列を埋め込まない。
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
   **587..1925-byte codec構造受理範囲**、1024-byte payload上限、variable field order、CRC32C、
   ownership、failure semanticsは
   [34章 §5.1](../34-v2-runtime-fabric-completion.md)をNormative candidateとする。
   `authority_id/authority_term/assignment_epoch`はclosed authority-binding groupとして、
   すべてzeroのABSENTまたはすべてnon-zeroのBOUNDだけを許可する。BOUNDは
   assignment/owner-governedまたはpolicy-required flowで必須、ABSENTは明示的に許可された
   controllerless/local/direct flowだけに許可する。reverse kindはtriggering attemptのgroupを
   bit-exact echoし、owner failoverは同一transactionのnew attemptにnew BOUND groupを使う。
   exact規則と6-kind required/zero matrixは34章§5.2を正本候補とする。3個のtext IDが各1 byte
   必須なので構造上の最小は`584 + 1 + 1 + 1 = 587`である。1925はcodec構造 ceilingであり、
   6-kind matrixではpayloadとevidenceを同時に非emptyにできないため、message意味論を満たす
   最大positive packetはAPPLICATIONの`584 + 63*3 + 1024 = 1797`である。1925-byte
   `payload=1024/evidence=128` packetはCRCが正しくてもkind matrixでrejectする。
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

1. **Path policy registry:** 下記canonical service identity digest、message kindから一意に
   導出するlogical direction/traffic classから、exact 1個のimmutable policy
   identity/revision/digestを決定する。multi-parent policyはさらにclosed
   `scope_endpoint_selector`（`SOURCE_RUNTIME=1`または
   `TARGET_RUNTIME=2`）をcanonical recordへ持つ。selectorが指す
   `source.runtime_id`または`target.target_runtime_id`を`endpoint_runtime_id`とし、
   all-zero、role/policy不一致をrejectする。Device/Installation IDの有無から推測しない。
   0件、複数match、digest conflictはattempt admission失敗とする。
2. **Authority/assignment registry:** concrete target + service scope + directionからexact 1個の
   FBC1 bindingを決定する。direct flowも暗黙zeroではなくstate ABSENTのrecordを必要とし、
   assignment/owner-governed flowはstate BOUNDのrecordを必要とする。
   単一owner profileでは少なくとも
   `{authority_id, authority_term, assignment_epoch}`、ADR-0020 multi-parent profileでは
   `owner_scope_id`と同ADRのfull downlink-owner tuple、canonical
   `owner_tuple_digest`をcopy-ownする。NFL1へ載る3-field authority groupはfull tupleの
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
`{transaction_id, attempt_id, message_kind, response_slot,
foundation_message_digest}`をkeyに次を1個のcanonical **attempt dispatch record**へ
copy-ownしてからpacket-linkへ渡す。

```text
message canonical digest
path policy identity / revision / digest
authority binding state、NFL1 3-field group、owner scope、owner tuple digest snapshot
descriptor + security + availability snapshot
selected path ID and selection epoch
encoded NFL1 digest and length
reservation identity / deadline / retry lifetime / state
```

`response_slot`はRECEIPTでは`receipt_stage`、DISPOSITIONでは`disposition`、
CANCEL_RESULTでは`cancel_kind`、他kindでは0である。`local_dispatch_id`は
`SHA-256(ASCII("NINLIL-FABRIC-LOCAL-DISPATCH-V1") || exact FBA1 key)`であり、同じimmutable
messageのretryは同じ値、progressive Receiptや別reverse kindは別値になる。APPLICATIONと
CANCEL_REQUESTは同じ`{transaction,attempt,kind}`に異なるFoundation digestを2件作れない。
reverse kindはFoundationが許す別kind/response slot/message digestだけを別dispatchとして保持できる。

同じdispatchの`WOULD_BLOCK` retryはこのrecordを再利用し、current registryから
policy、authority、security、availabilityを取り直してsilent upgrade/downgradeしない。
snapshotのhard expiry、authority fence、security revocation、compliance denyはrecord再利用より
優先し、TX 0とする。別pathへ再選択する場合は上位Runtimeがnew attempt IDを発行した後だけ
新recordを作る。同じattempt IDで異なるmessage digest、policy、authority、selected pathを
受けた場合はconflictとして送信0にする。

FBA1は200-byte full owner tupleをcopy-ownしたとは主張しない。copy-ownするのは
`authority_state/ID/term/assignment_epoch`、`owner_scope_id`、canonical
`owner_tuple_digest`のsnapshotだけである。`RETRYABLE_NO_ACCEPT`の再試行では、再提示された
Foundation messageのsource/target/service、pin済みpolicyのdirection/traffic/scope selectorから
bounded FBC1 lookup keyを再構成し、exact 1件のcurrent FBC1を読み、state、3-field group、
owner scope/digestがFBA1 snapshotとbit-exact一致してからだけPREPAREDへ戻す。full tuple自体は
そのCRC/digest-valid FBC1から得る。0件、複数件、期限切れ、digest conflictではTX 0でCLOSEDへ進む。
restart時のPREPARED/LINK_RETAINEDは再送せずFENCED_UNKNOWNへ進むため、FBA1単独からfull tupleや
packet bytesを復元する必要はない。この二経路以外でFBA1 digestからtupleを推測しない。

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

### Canonical service/policy selector

Foundation service identityから次のbyte列`S`をfieldごとに作る。

```text
u16 namespace_length || namespace bytes
u16 service_length   || service bytes
u16 schema_length    || schema bytes
u64 descriptor_revision
u16 descriptor_digest_algorithm (=1) || descriptor_digest[32]
u16 schema_major || u16 schema_minor || u32 family
```

`service_identity_digest =
SHA-256(ASCII("NINLIL-FABRIC-SERVICE-IDENTITY-V1") || S)`とする。text lengthは各1..63、
integerはbig-endianで、C struct/padding/unused text bytesを入力しない。

policy `direction`は`FORWARD=1`（APPLICATION/CANCEL_REQUEST）または
`REVERSE=2`（RECEIPT/DISPOSITION/CUSTODY_ACCEPTED/CANCEL_RESULT）だけである。
`traffic_class`は`APPLICATION=1`（APPLICATION/RECEIPT/DISPOSITION/CUSTODY_ACCEPTED）または
`CONTROL=2`（CANCEL_REQUEST/CANCEL_RESULT）だけである。この二値はold
`ninlil_bearer_message_t.kind`から一意に導出し、device/site、priority、provider kindから推測しない。

## Private Fabric API candidate v1

### 採番と公開境界

- Runtime Platform ABI: `NINLIL_ABI_VERSION=0x0001`、単一
  `const ninlil_bearer_ops_t *bearer`のまま不変
- private Fabric source API candidate: `NINLIL_FABRIC_PRIVATE_API_VERSION=0x0001`
- NFL1: logical envelope version 1候補。Ninlil public application data wireではない
- Fabric storage: dedicated namespace `ninlil.fabric.v1`、schema 1候補
- build feature: `NINLIL_ENABLE_PRIVATE_FABRIC_V1=OFF`がdefault。ONでもheaderをinstallせず、
  shared-library export symbol、pkg-config/CMake public target、public compatibility matrixへ載せない

本ADR受入だけでpublic Fabric APIを割り当てない。将来public化する場合はprivate name/layoutを
そのままstable ABIとみなさず、新しいADR、ABI manifest、old/new compile/link matrixを要する。
既存利用者はFabricを使わず従来Bearerを渡せる。Fabric利用者だけが下記adapterから得た1個の
既存`ninlil_bearer_ops_t`を既存slotへ渡す。

### Exact type/status catalog

以下はdocs-onlyのexact C source contract候補である。`u8/u16/u32/u64`は
`uint8_t/uint16_t/uint32_t/uint64_t`、IDは既存`ninlil_id128_t`である。全input structは先頭に
`uint16_t api_version; uint16_t struct_size;`を持ち、version 1の`struct_size`と全reserved=0だけを
受理する。private v1ではsmall/large struct互換を推測せずexact size以外を`INVALID_ARGUMENT`とする。

```c
typedef struct ninlil_fabric_private ninlil_fabric_private_t;
typedef struct ninlil_fabric_registration_private
    ninlil_fabric_registration_private_t;
typedef void *ninlil_fabric_packet_link_handle_t;
typedef void *ninlil_fabric_packet_token_t;

typedef uint32_t ninlil_fabric_private_status_t;
#define NINLIL_FABRIC_PRIVATE_OK              0u
#define NINLIL_FABRIC_PRIVATE_INVALID_ARGUMENT 1u
#define NINLIL_FABRIC_PRIVATE_WRONG_THREAD    2u
#define NINLIL_FABRIC_PRIVATE_REENTRANT       3u
#define NINLIL_FABRIC_PRIVATE_CLOSED          4u
#define NINLIL_FABRIC_PRIVATE_CONFLICT        5u
#define NINLIL_FABRIC_PRIVATE_UNSUPPORTED     6u
#define NINLIL_FABRIC_PRIVATE_CORRUPT         7u
#define NINLIL_FABRIC_PRIVATE_COMMIT_UNKNOWN  8u
#define NINLIL_FABRIC_PRIVATE_DENIED          9u
#define NINLIL_FABRIC_PRIVATE_UNAVAILABLE    10u
#define NINLIL_FABRIC_PRIVATE_CAPACITY       11u
#define NINLIL_FABRIC_PRIVATE_WOULD_BLOCK    12u

typedef uint32_t ninlil_fabric_link_status_t;
#define NINLIL_FABRIC_LINK_OK                 0u
#define NINLIL_FABRIC_LINK_EMPTY              1u
#define NINLIL_FABRIC_LINK_RETAINED           2u
#define NINLIL_FABRIC_LINK_WOULD_BLOCK        3u
#define NINLIL_FABRIC_LINK_UNAVAILABLE        4u
#define NINLIL_FABRIC_LINK_DENIED             5u
#define NINLIL_FABRIC_LINK_LOST_UNKNOWN       6u
#define NINLIL_FABRIC_LINK_CORRUPT            7u

typedef uint32_t ninlil_fabric_link_completion_kind_t;
#define NINLIL_FABRIC_LINK_COMPLETION_PENDING          1u
#define NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE   2u
#define NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE 3u
#define NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN     4u
```

descriptor catalogs are closed in candidate v1:

```c
#define NINLIL_FABRIC_LINK_KIND_LOOPBACK 1u
#define NINLIL_FABRIC_LINK_KIND_WIFI     2u
#define NINLIL_FABRIC_LINK_KIND_USB      3u
#define NINLIL_FABRIC_LINK_KIND_RF       4u

#define NINLIL_FABRIC_LINK_DIRECTION_SEND    (1u << 0)
#define NINLIL_FABRIC_LINK_DIRECTION_RECEIVE (1u << 1)

#define NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE (1u << 0)
#define NINLIL_FABRIC_CAP_UNICAST          (1u << 1)
#define NINLIL_FABRIC_CAP_BROADCAST        (1u << 2)
#define NINLIL_FABRIC_CAP_RESERVATION      (1u << 3)
#define NINLIL_FABRIC_CAP_REGULATED_RF     (1u << 4)
#define NINLIL_FABRIC_CAP_CUSTODY          (1u << 5)
#define NINLIL_FABRIC_CAP_EVIDENCE         (1u << 6)

#define NINLIL_FABRIC_SECURITY_INTEGRITY         (1u << 0)
#define NINLIL_FABRIC_SECURITY_CONFIDENTIALITY   (1u << 1)
#define NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION (1u << 2)
#define NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS (1u << 3)

#define NINLIL_FABRIC_PEER_CAP_NFL1_V1 (1u << 0)

#define NINLIL_FABRIC_POLICY_DIRECTION_FORWARD 1u
#define NINLIL_FABRIC_POLICY_DIRECTION_REVERSE 2u
#define NINLIL_FABRIC_TRAFFIC_APPLICATION      1u
#define NINLIL_FABRIC_TRAFFIC_CONTROL          2u

#define NINLIL_FABRIC_AUTHORITY_ABSENT 0u
#define NINLIL_FABRIC_AUTHORITY_BOUND  1u
```

unknown kind/bitはUNSUPPORTED、direction mask 0、instance/security profile/peer Runtime/
Attachment authority/attestation clock epochのzero ID、descriptor/config revision 0、digest zero、maximum packet/transfer
outside 587..1925、latency/cost class `UINT16_MAX`（0..65534だけvalid）、reservation capabilityなしの
non-zero capacity、attestation epoch 0はINVALID_ARGUMENT、well-formedだが既にexpired/revokedな
attestationはDENIEDとしてregistration前にrejectする。RF kindは
`CAP_REGULATED_RF`必須、non-RF kindでは同bitを禁止する。policy candidate
`reservation_units`は1以上で、selected FBR1 capacity以下でなければineligibleである。
`maximum_transfer_bytes`は`maximum_packet_bytes`以上である。v1では1 NFL1を越えるtransferを
admitしないため両上限とも1925を超えない。
attestation/availability expiryはstored clock epochとcurrent trusted Clock epochがbit-exactな場合だけ
比較し、epoch mismatch/uncertain sampleではexpiredでないと推測せずDENIED/ineligibleとする。
`peer_nfl1_version`はexact 1、peer capabilityはknown mask内かつ`PEER_CAP_NFL1_V1`必須である。
0/2/unknown version、unknown capability、NFL1 bitなしはregistrationをUNSUPPORTEDで拒否し、
raw struct fallback、zero補完、別versionへのdowngradeを行わない。

NFL1のdescriptor/content/route digest algorithmはそれぞれexact `SHA-256=1`、familyは
Foundationで定義済みのclosed known value、Receipt stage、Disposition、effect certainty、
retry guidance、cancel kind、evidence time trustも各Foundation closed catalogのknown valueだけを
受理する。該当message kindでunknown enum、またはalgorithm 0/2/unknownを見た場合は
`UNSUPPORTED/CORRUPT`でdecode/project 0とし、unknown値をdefault、zero、別kindへ写像しない。

unknown status、statusとout shapeの矛盾、non-zero reservedは`CORRUPT`でfail closedする。
private API callのvalidation precedenceは
`NULL/header/size/reserved -> owner thread -> re-entry -> lifecycle -> identity/revision conflict ->
unsupported -> durable corruption/COMMIT_UNKNOWN -> deny -> unavailable -> capacity -> temporary busy`
の順で、先に成立した1個だけを返す。outputはcall前zero/NULLとし、`OK`以外では、required
workspace sizeを返す専用callを除き変更しない。

### Exact descriptor、policy、packet-link callback

APIが参照するfixed input structは次である。digest arrayはopaque 32 bytesで、algorithmは
candidate v1でSHA-256=`1`固定のためstructへ別fieldを持たない。C struct memoryをhash/persistせず、
後述canonical payload encoderへfieldごとに渡す。

```c
#define NINLIL_FABRIC_PROFILE_1 1u

typedef struct ninlil_fabric_config_v1 {
    uint16_t api_version, struct_size;
    uint32_t profile_id;                 /* exact 1 */
    uint32_t flags;                      /* exact 0 */
    const ninlil_storage_ops_t *storage;
    const ninlil_clock_ops_t *clock;
    const ninlil_execution_ops_t *execution;
} ninlil_fabric_config_v1_t;

typedef struct ninlil_fabric_link_descriptor_v1 {
    uint16_t api_version, struct_size;
    ninlil_id128_t instance_id;
    uint32_t link_kind, direction_mask, capability_flags;
    uint64_t descriptor_revision;
    uint8_t descriptor_digest[32];
    ninlil_id128_t security_profile_id;
    uint32_t security_capability_flags;
    uint8_t security_binding_digest[32];
    uint64_t attestation_epoch;
    ninlil_id128_t attestation_clock_epoch_id;
    uint64_t attestation_expires_at_ms;
    uint8_t attestation_digest[32];
    ninlil_id128_t authenticated_peer_runtime_id;
    ninlil_id128_t attachment_authority_id;
    uint8_t attachment_binding_digest[32];
    uint32_t maximum_packet_bytes, maximum_transfer_bytes;
    uint16_t latency_class, cost_class;
    uint16_t reservation_capacity, reserved_zero_u16;
    uint16_t peer_nfl1_version, reserved_zero_peer_u16;
    uint32_t peer_fabric_capability_flags;
    uint64_t configuration_revision;
    uint8_t configuration_digest[32];
} ninlil_fabric_link_descriptor_v1_t;

typedef struct ninlil_fabric_policy_candidate_v1 {
    ninlil_id128_t instance_id;
    uint16_t rank, flags, reservation_units, reserved_zero;
} ninlil_fabric_policy_candidate_v1_t;

typedef struct ninlil_fabric_path_policy_v1 {
    uint16_t api_version, struct_size;
    ninlil_id128_t policy_id;
    uint64_t revision;
    uint8_t canonical_digest_zero_on_input[32];
    uint8_t service_identity_digest[32];
    uint32_t family, direction;
    uint16_t traffic_class, scope_selector;
    uint32_t required_capability_flags, required_security_flags;
    uint16_t maximum_latency_class, maximum_cost_class;
    uint32_t minimum_packet_bytes;
    uint8_t authority_mode;
    uint8_t reserved_zero_u8[3];
    uint64_t deadline_guard_ms;
    uint16_t candidate_count, reserved_zero_u16;
    uint32_t reserved_zero_u32;
    ninlil_fabric_policy_candidate_v1_t candidates[8];
} ninlil_fabric_path_policy_v1_t;

typedef struct ninlil_fabric_authority_binding_v1 {
    uint16_t api_version, struct_size;
    ninlil_id128_t binding_id;
    uint8_t service_identity_digest[32];
    uint32_t family, direction;
    uint16_t traffic_class, scope_selector;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_id128_t target_runtime_id;
    ninlil_id128_t target_application_id;
    ninlil_id128_t policy_id;
    uint64_t policy_revision;
    uint8_t policy_digest[32];
    uint32_t authority_state; /* ABSENT=0, BOUND=1 */
    ninlil_id128_t authority_id;
    uint64_t authority_term;
    uint32_t assignment_epoch, reserved_zero_u32;
    ninlil_id128_t owner_scope_id;
    uint8_t owner_tuple_digest[32];
    uint8_t owner_tuple_canonical[200];
    ninlil_id128_t authority_clock_epoch_id;
    uint64_t lease_expires_at_ms;
    uint64_t assignment_revision;
    uint64_t reserved_zero_u64;
} ninlil_fabric_authority_binding_v1_t;

typedef struct ninlil_fabric_link_metrics_v1 {
    uint16_t api_version, struct_size;
    uint32_t queued_items, retained_tokens;
    uint64_t accepted_count, would_block_count, unavailable_count;
    uint64_t denied_count, lost_unknown_count, corrupt_count;
    uint64_t metrics_revision;
} ninlil_fabric_link_metrics_v1_t;
```

configの3 ops pointerと各ops structはcreate call中borrowし、Fabricがstruct/function/user pointer
valueをcopyする。`storage/clock/execution` struct自体の元addressはreturn後参照しないが、copyした
function codeとnon-NULL user pointeeはdestroyまでcaller所有で有効である。Storageはcreate中に
exact namespace `ninlil.fabric.v1`、expected schema 1でopenする。

`ninlil_fabric_link_descriptor_v1_t`は、Storage §後述のFBR1 payload offset 0..263、
peer version/capability offset 300..307、`configuration_revision/configuration_digest`
offset 308..347を同じ順・幅で持つ固定value structである。
availability/lifecycle offset 264..299はregistration inputではなくproviderの`state` outputである。
instance IDはnon-zero、同一IDの再登録は全fieldとops function/user pointer valueがbit/value exactなら
同じregistration handleを返すidempotent attach、1 fieldでも異なれば`CONFLICT`である。
`link_kind`の一致はidentity一致ではない。同じkindの異なるnon-zero instance IDを最大16個登録できる。
descriptor、security profile/binding/attestation、peer Runtime、Attachment authority/binding、
configurationはinstance lifetimeでimmutableで、更新は旧instanceのhot unregisterと新しい
instance IDのregisterだけである。availability state/epoch/expiryだけを同じinstanceで更新できる。

`ninlil_fabric_path_policy_v1_t`はFBP1 payload 328 bytesと同じ固定fieldを持つが、
offset 24のcanonical digestはcallerがzeroにして渡す。Fabricは
`SHA-256(ASCII("NINLIL-FABRIC-POLICY-V1") || payload_with_digest_zero)`を計算してcopy-ownし、
保存/publishする。同一policy ID/revisionはexact digestだけidempotent、new revisionはcurrent+1だけ、
revision wrap/rollback/gapは`CONFLICT`とする。候補配列は固定8 entry、`candidate_count`より後は
all-zero必須である。

`ninlil_fabric_authority_binding_v1_t`はFBC1 payload 488 bytesと同じfield順・幅を持つ。
binding ID、service/policy/endpoint/target identity、assignment revisionはnon-zeroである。
ABSENTではauthority ID/term/epoch、owner scope/tuple digest/canonical、authority clock/leaseをすべてzero、
BOUNDではそれらをすべてnon-zeroとし、trusted current Clockと同epochで
`now_ms < lease_expires_at_ms`だけをeligibleとする。同一binding IDのexact replayはidempotent、
replacementはassignment revision exact +1だけで、policy/endpoint lookup identityはimmutableである。
put/removeはFBC1と参照するFBM1 revisionを同じFULL transactionで更新し、COMMIT_UNKNOWNは
all-old/all-newだけをfresh READ_ONLYで分類する。0件はUNAVAILABLE、同じ
`{service digest,family,direction,traffic class,endpoint runtime,target runtime,target application,
policy ID/revision/digest}`へ2 binding以上はCORRUPTである。FBA/FBT参照中またはretention前はremoveしない。
policy `BOUND_REQUIRED`はBOUNDだけ、`ABSENT_ALLOWED`は明示ABSENTまたはBOUNDを受理する。
ABSENT_ALLOWEDでrecord 0件をABSENTへzero補完せず、stateとpolicy modeが矛盾すればDENIEDとする。
BOUND owner tuple canonical 200 bytesは
`owner_scope[16] @0, assignment_revision u64 @16, owner_controller[16] @24,
owner_cell[16] @40, direction u32 @56, e2e_context[16] @60, key_generation u64 @76,
e2e_security_id[16] @84, e2e_security_epoch u64 @100, e2e_binding_digest[32] @108,
authority_clock_epoch[16] @140, lease_expires_at_ms u64 @156,
handoff_token_digest[32] @164, reserved u32=0 @196`である。outer duplicate fieldsはbit-exact一致し、
owner tuple digestは
`SHA-256(ASCII("NINLIL-FABRIC-OWNER-TUPLE-V1") || canonical[200])`である。

packet-link vtableとcall shapeは次で固定する。

```c
typedef struct ninlil_fabric_packet_view_v1 {
    uint16_t api_version, struct_size;
    const uint8_t *bytes;          /* borrowed NFL1 */
    uint32_t length;               /* 587..1925 structural */
    uint32_t reserved_zero;
    ninlil_id128_t transaction_id;
    ninlil_id128_t attempt_id;
    ninlil_id128_t selected_path_id;
    uint64_t path_selection_epoch;
    const ninlil_tx_permit_t *permit; /* borrowed; RFで必須 */
} ninlil_fabric_packet_view_v1_t;

typedef struct ninlil_fabric_link_completion_v1 {
    uint16_t api_version, struct_size;
    uint32_t kind;
    uint32_t reserved_zero;
} ninlil_fabric_link_completion_v1_t;

typedef struct ninlil_fabric_link_state_v1 {
    uint16_t api_version, struct_size;
    uint64_t availability_epoch;
    ninlil_id128_t availability_clock_epoch_id;
    uint64_t available_until_ms;
    uint32_t available;            /* exact 0 or 1 */
    uint32_t reserved_zero;
} ninlil_fabric_link_state_v1_t;

typedef struct ninlil_fabric_packet_link_ops_v1 {
    uint16_t api_version, struct_size;
    void *user;
    ninlil_fabric_link_status_t (*open)(
        void *user, ninlil_fabric_packet_link_handle_t *out_handle);
    void (*close)(void *user, ninlil_fabric_packet_link_handle_t handle);
    ninlil_fabric_link_status_t (*start_send)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        const ninlil_fabric_packet_view_v1_t *packet,
        ninlil_fabric_packet_token_t *out_token);
    ninlil_fabric_link_status_t (*poll_send)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token,
        ninlil_fabric_link_completion_v1_t *out_completion);
    ninlil_fabric_link_status_t (*cancel_send)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token);
    void (*release_send)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_packet_token_t token);
    ninlil_fabric_link_status_t (*receive_next)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        const uint8_t **out_bytes, uint32_t *out_length,
        void **out_receive_token);
    void (*release_received)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        void *receive_token);
    ninlil_fabric_link_status_t (*state)(
        void *user, ninlil_fabric_packet_link_handle_t handle,
        ninlil_fabric_link_state_v1_t *out_state);
} ninlil_fabric_packet_link_ops_v1_t;
```

`open`は`OK+non-NULL`だけがsuccessで、non-OKではNULLである。`start_send`は
`RETAINED+non-NULL token`または`WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN/CORRUPT+NULL`だけが
validである。`RETAINED`を返す前にproviderは全NFL1 bytesとretry stateをbounded storageへ
copy-ownする。TCP/TLS partial writeはこのretry stateの内部進捗であり、`WOULD_BLOCK`として
上位へ返さない。`poll_send`はFabricからだけ呼び、`OK+PENDING`または`OK+terminal kind`だけを返す。
terminalまたは`cancel_send` terminal後にFabricが`release_send`をexactly 1回呼ぶ。
`cancel_send`のvalid returnはOK（definite terminal）またはLOST_UNKNOWNだけで、WOULD_BLOCKを含む
他statusはCORRUPT/unknown fenceである。`start_send`のnon-RETAINED statusではprovider token 0だが、
LOST_UNKNOWNだけはwire side effect可能性を保持する。Fabric retain後の全start/poll/cancel terminalは
outer ACCEPTEDを遡及変更せず、automatic upper duplicate 0である。
`receive_next`のbytesはprovider所有で、FabricがNFL1 decode workspaceへcopyした後
`release_received`をexactly 1回呼ぶ。failure/EMPTYではtoken/bytes/lengthはzeroでrelease 0である。

providerからFabricへのcallback関数は存在しない。全vtable callはFabric owner contextの
`step`/Bearer callから同期的にだけ起き、providerはそのcall中にFabric/private API、
Runtime API、同じvtableへ再入しない。`user` pointer valueとvtableはregistration時にcopyする。
non-NULL `user` pointeeとfunction codeはunregister完了またはFabric destroyまでcaller所有で有効、
Fabricはfreeしない。packet view/permitはcall returnまでborrow、opaque provider handle/tokenは
provider所有、Fabric workspace/registration handleはcallerがfreeしない。

### Exact private functionsとopaque lifecycle

```c
ninlil_fabric_private_status_t ninlil_fabric_private_workspace_required_v1(
    uint32_t profile_id, uint32_t *out_bytes, uint32_t *out_alignment);
ninlil_fabric_private_status_t ninlil_fabric_private_create_v1(
    const ninlil_fabric_config_v1_t *config,
    void *workspace, uint32_t workspace_bytes,
    ninlil_fabric_private_t **out_fabric);
ninlil_fabric_private_status_t ninlil_fabric_private_bearer_ops_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_bearer_ops_t **out_bearer_ops);
ninlil_fabric_private_status_t ninlil_fabric_private_register_link_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_registration_private_t **out_registration);
ninlil_fabric_private_status_t ninlil_fabric_private_unregister_begin_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration);
ninlil_fabric_private_status_t ninlil_fabric_private_unregister_poll_v1(
    ninlil_fabric_private_t *fabric,
    ninlil_fabric_registration_private_t *registration,
    uint32_t *out_done);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_path_policy_v1_t *policy);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *policy_id, uint64_t revision);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_put_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_fabric_authority_binding_v1_t *binding);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_remove_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id, uint64_t assignment_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_authority_snapshot_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *binding_id,
    ninlil_fabric_authority_binding_v1_t *out_binding);
ninlil_fabric_private_status_t ninlil_fabric_private_link_snapshot_v1(
    ninlil_fabric_private_t *fabric, const ninlil_id128_t *instance_id,
    ninlil_fabric_link_descriptor_v1_t *out_descriptor,
    ninlil_fabric_link_state_v1_t *out_state);
ninlil_fabric_private_status_t ninlil_fabric_private_policy_snapshot_v1(
    ninlil_fabric_private_t *fabric, const ninlil_id128_t *policy_id,
    uint64_t revision, ninlil_fabric_path_policy_v1_t *out_policy);
ninlil_fabric_private_status_t ninlil_fabric_private_metrics_snapshot_v1(
    ninlil_fabric_private_t *fabric, const ninlil_id128_t *instance_id,
    ninlil_fabric_link_metrics_v1_t *out_metrics);
ninlil_fabric_private_status_t ninlil_fabric_private_step_v1(
    ninlil_fabric_private_t *fabric, uint32_t work_budget,
    uint32_t *out_work_done);
ninlil_fabric_private_status_t ninlil_fabric_private_dispatch_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *attempt_id,
    uint32_t message_kind, uint32_t response_slot,
    const uint8_t foundation_message_digest[32],
    uint64_t runtime_terminal_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_trigger_release_v1(
    ninlil_fabric_private_t *fabric,
    const ninlil_id128_t *transaction_id,
    const ninlil_id128_t *triggering_attempt_id,
    uint32_t triggering_kind,
    uint64_t runtime_terminal_revision);
ninlil_fabric_private_status_t ninlil_fabric_private_close_begin_v1(
    ninlil_fabric_private_t *fabric);
ninlil_fabric_private_status_t ninlil_fabric_private_close_poll_v1(
    ninlil_fabric_private_t *fabric, uint32_t *out_done);
ninlil_fabric_private_status_t ninlil_fabric_private_destroy_v1(
    ninlil_fabric_private_t *fabric);
```

全functionの明示pointer parameterはnon-NULL必須である。例外はops内`user`だけで、NULLもvalid
valueとしてcopyする。descriptor/policy/config、workspace、opaque handle、out storage、
packet bytes、outer `permit`、全required vtable function pointerのNULLは最初の
`INVALID_ARGUMENT/CORRUPT`である。callerはopaque outをNULL、scalar/struct outをzeroにして呼ぶ。
private functionはsuccess時だけ全outを書き、failure時は変更しない。Fabricがlink vtableを呼ぶ前は
token/bytes/lengthをNULL/0、completion/stateをcurrent header+他zeroに初期化する。provider
non-successはこれらを変更せず、矛盾時はunexpected tokenを対応release/closeしてCORRUPTへfenceする。
snapshotはowner-thread point-in-time copyで、returned struct内にFabric pointer/borrowed viewを
含めない。unknown ID/revisionはUNAVAILABLE、revision 0はINVALID_ARGUMENTである。metricsはdurable
selection authorityでなくvolatile diagnosticで、counterはchecked +1、overflow時はinstanceを
CORRUPT/fencedにしてwrapしない。
metrics revisionはregistration時1、上表counterまたはqueued/retained valueが実際に変わるたび
strict +1、snapshot/poll/restartだけでは増やさない。

`ninlil_fabric_config_v1_t`はexact profile ID、Foundation Storage/Clock/Execution ops pointer、
dedicated storage namespace `ninlil.fabric.v1`、flags=0を持つfixed structで、全ops structをcreate中に
copyする。workspaceはcaller所有、profile 1では198,656 bytes、alignmentはC
`_Alignof(max_align_t)`。create成功からdestroy成功までcallerはworkspaceと、copy済みopsの
non-NULL user pointee/function codeを変更・解放しない。hidden heap/VLAは使用しない。
createは`execution.current_context_id`をexactly 1回呼び、non-zero resultをowner contextとして
copy-ownする。全private functionとouter Bearer methodはnested pointerやStorage/Clock/providerを
呼ぶ前にcurrent contextをexactly 1回取得して比較し、不一致はWRONG_THREAD、provider call中の
再入はREENTRANTとする。create途中でStorage open後に失敗した場合はlive iterator/transactionを
close/rollbackしてStorage handleをexactly 1回closeし、out NULL、provider open 0である。

lifecycleは`ZERO -> OPEN -> CLOSING -> CLOSED -> DESTROYED`だけである。create failureは
out NULL/workspace ownership移転0。bearer ops pointerはFabric所有borrowed pointerでdestroyまで
stable、adapterのouter handleは同時exact 1個、二つ目のopenは`WOULD_BLOCK`である。
normal owner orderは`Fabric create -> link register/policy put -> Runtime create(outer open) ->
Runtime destroy(outer close) -> Fabric close_begin/step/close_poll -> Fabric destroy`である。
Fabric closeをRuntime destroyより先に始めた場合はnew outer sendをUNAVAILABLEで閉じるが、outer
handleをFabric側からfreeせずRuntimeのcloseを待つ。
registry 0でもouter openはOK+non-NULLで、stateはFBM1のnon-zero epoch/available=0を返す。
available=1は少なくとも1 ACTIVE instanceとshared queue admission capacityがあるときだけである。
`unregister_begin`はACTIVE instanceをDRAININGへexact 1回遷移し、新規selectionから即除外するが、
保持済みpacket/tokenを捨てない。`unregister_poll`はprogressを行わず、retained token/queueが0になり
provider `close`をexactly 1回呼んだときだけ`out_done=1`としてregistration handleをconsumeする。
inflightがある間は`OK+done=0`で、同じinstance IDを再登録しない。beginのDRAINING repeatは
`CONFLICT`、consume後handleを再利用しない。

`close_begin`はouter open/send、新規register/policy mutationを閉じ、全registrationをDRAININGにする。
`step`だけが既存queue/tokenを進める。`close_poll done=1`で全queue/token/receive loan/registration/
outer handle/timerが0、全provider close済み、Storage transaction/iterator 0である。destroyは
CLOSEDでだけ成功して全workspaceをzero化しhandleをconsumeする。途中destroyは`WOULD_BLOCK`で
handle/workspace不変。`close_begin`はOPENでOK、CLOSINGでidempotent OK、CLOSEDでCLOSEDを返す。
process強制終了をgraceful unregister/destroyと主張しない。
最後のclose_pollはStorage transaction/iterator 0を確認してdedicated Storage handleをexactly 1回
closeした後だけdone=1/CLOSEDをpublishする。destroyはStorage/provider Portを追加callしない。

## Foundation outer Bearer semantics

Fabric adapterは12/14章のsingle-Bearer contractを変更しない。`send`のexact sequenceは次である。

1. argument/output/header、same-attempt conflict、policy/authority/securityを検証する。
2. immutable policy revisionを解決し、eligible setとstable sortでselected instanceを決める。
3. queue slot、1925-byte packet buffer、attempt slot、timer slotを**全部**予約する。
4. Foundation messageをNFL1へenrich/copyし、call-scoped permitの
   `{retry_lifetime_clock_epoch_id, permit_id, permit_expires_at_ms,
   permit_claim_state=CLEAR}`を同居させたFBA1 PREPAREDを`FULL` commitする。
   `retry_lifetime_clock_epoch_id`はpermit clock authorityも兼ねる。
5. selected instanceのcurrent lifecycle/availability epoch/expiry/revocation/authority/
   TxPermitを再検証する。不一致ならFBA1をCLOSEDへ`FULL` replacementし、reservation/queue/timerを
   releaseしてからexact failureを返す。CLOSED commitがCOMMIT_UNKNOWNならLOST_UNKNOWN、
   definite failureならCORRUPT/fenceで、PREPAREDを通常return後のactive reservationに残さない。
6. NFL1全bytesをreserved Fabric queueへtentative copyし、provider call直前に同じFBA1を
   bit-exact OLD→NEWの`FULL` replacementして`permit_claim_state=CLEAR`から`CLAIMED`へ進める。
   別key/別recordのpermit ledgerは作らない。claim failure/`COMMIT_UNKNOWN`ではproviderを呼ばず、
   `LOST_UNKNOWN`へ進む。CU-NEWでCLAIMEDが残った場合もそのcallではprovider start 0で、
   restart reconcileはFENCED_UNKNOWNにし、same pairを再利用しない。claim OK後、
   **同じouter send call中**にprovider `start_send`をexactly 1回呼ぶ。packet viewの
   permitはouter inputをcall中だけborrowし、Fabricはpointer/valueを後続stepへ保存しない。
   providerはtransaction/kind/digest/logical bytes/current time/reuseを独立に照合し、全NFL1/retry
   stateをcopy-ownした場合だけRETAINED+tokenを返す。providerがNULL tokenで
   WOULD_BLOCK/UNAVAILABLE/DENIEDを返した場合だけ、Fabricはstate transitionと
   `CLAIMED→CLEAR`を**同じFBA1 FULL replacement**で確定してから同名outer statusを返す。
   CU-NEWはexact intended rowとして扱えるが、OLD/partial/CRC-valid third/definite failureでは
   `LOST_UNKNOWN`でCLAIMEDをfail-closedに扱う。
7. provider RETAINEDではCLAIMEDを保持したままFBA1をLINK_RETAINEDへ`FULL` replacementする。
   commit OKだけがouter
   `OK+SEND_ACCEPTED` pointである。commit failure/COMMIT_UNKNOWNはprovider side effect可能なので
   LOST_UNKNOWN/fence、automatic duplicate 0である。provider WOULD_BLOCKはFBA1を
   RETRYABLE_NO_ACCEPT+CLEARへ前項の単一FULL replacementで進め、tentative copy/reservationをreleaseし、outer
   WOULD_BLOCKとする。同じdispatch exact retryだけがRETRYABLE_NO_ACCEPT→PREPAREDを許す。
   UNAVAILABLE/DENIEDはCLOSED replacement後に同名outer status、LOST_UNKNOWN/CORRUPT/invalid shapeは
   CLAIMEDを保持したFENCED_UNKNOWN recoveryとし、permit pointerを後続stepへ持ち越さない。

private reference candidateでは、durable claim authorityを同じattemptのFBA1だけに置く。
packet-link providerのbounded LIVE/RETIRED ledgerは同時所有権だけを管理し、terminal
`release_send`後にslotを回収してよい。TxGate issue contractは同じ
`(clock_epoch_id, permit_id)`を生涯再発行してはならず、Fabricはopen/reload時にも別FBA1間の
pair重複をCORRUPT/TX 0とする。providerをFabricのcall-scoped outer authorityなしに直接使う構成は
`DENIED + TX 0`である。有限provider ringだけをpermanent replay authorityにしてはならない。
claimはprovider side effectの**前**に同じFBA1へ保存する。provider RETAINED後に初めてclaimを
書く順序は禁止する。通常のdefinite non-acceptだけがstate+CLEARの同一FULLを許す。

ownership transfer前にqueue/providerが0 byteを保持し、一時capacityだけが理由なら
`NINLIL_BEARER_WOULD_BLOCK`である。transfer後にprovider未call/WOULD_BLOCKの状態はない。
TCP/TLS partialはproviderが全packet/retry stateを保持しRETAINEDを返した後の内部進捗なので
`NINLIL_BEARER_OK + NINLIL_BEARER_SEND_ACCEPTED`を返す。providerだけが同じNFL1 packetを
retryし、Runtimeへ同dispatchのduplicate sendを要求しない。DURABLE_CUSTODYはremote FULL evidenceを
得た別contractだけであり、local queue/FBA1 commitから生成しない。

outer `send` status precedenceは次で固定する。

| First condition | Exact outer result | Ownership / TX |
| --- | --- | --- |
| malformed/unknown/conflicting same attempt、invalid provider shape、storage corrupt | `NINLIL_BEARER_CORRUPT` | transfer 0、TX 0 |
| PREPARED/CLOSED write `COMMIT_UNKNOWN`または既存fence | `NINLIL_BEARER_LOST_UNKNOWN` | provider start 0、reconcile前reencode/reselect 0 |
| pre-provider FBA1 CLEAR→CLAIMED failure/`COMMIT_UNKNOWN` | `NINLIL_BEARER_LOST_UNKNOWN` | provider start 0、CU-NEW claimもsame-call再利用0、上位automatic retry 0 |
| provider RETAINED後のLINK_RETAINED write failure/`COMMIT_UNKNOWN` | `NINLIL_BEARER_LOST_UNKNOWN` | FBA1 CLAIMED保持、provider token fence、上位duplicate 0 |
| provider definite non-accept後のstate+CLEAR FULLがOLD/partial/third/failure | `NINLIL_BEARER_LOST_UNKNOWN` | TX accepted 0、claimはfail-closed、同じPermit IDの自動再利用0 |
| authority/security/compliance/policyのexplicit hard deny、RF TxPermit invalid | `NINLIL_BEARER_DENIED` | transfer 0、TX 0 |
| policy 0/multiple match、eligible path 0、path/peer/attachment unavailable/expired、MTU unsupported | `NINLIL_BEARER_UNAVAILABLE` | transfer 0、TX 0 |
| eligibleだがqueue/attempt/timer/workspace/storage logical capacity不足、provider未保持 | `NINLIL_BEARER_WOULD_BLOCK` | transfer 0、permit未消費、TX 0 |
| same-call FBA1 CLAIMED FULL + provider RETAINED + FBA1 LINK_RETAINED FULL commit OK | `OK + SEND_ACCEPTED` | permit consumed、ownership移転、上位duplicate 0 |

`LOST_UNKNOWN`をWOULD_BLOCKへ、DENIEDをUNAVAILABLEへ、capacityをpath absenceへ変換しない。
Fabric logical `state.available=1`は「少なくとも1 policyで将来選択可能」ではなく、owner Runtimeに
対する新規send admissionのcapacityと1個以上のACTIVE linkがあるというcoarse hintだけである。
actual policy denial/absenceをsend時に再評価する。availability epochはFoundation規則どおりnon-zero
strict incrementで、same epoch/different state、wrap、restart rollbackはCORRUPT/fail closedである。

packet-link `start_send`はouter send callごとexact 1回で、borrowed public permitを後続stepへ
再利用しない。provider WOULD_BLOCK後のsame dispatch reinvokeはFoundationがfresh permitで同じ
immutable messageを再びouter sendへ渡したときだけで、Fabric自身のstart retry timerは作らない。
RETRYABLE_NO_ACCEPTの旧FBA1は旧permit pairをCLEARで保持し、exact retryは同じpairを拒否する。
fresh call-scoped permitの`(clock_epoch_id, permit_id)`が旧pairおよび全FBA1と異なることを確認し、
RETRYABLE_NO_ACCEPT→PREPARED、fresh permit ID/expiry、CLEAR→CLAIMEDを同じFBA1 FULL replacementで
確定してからだけproviderを呼ぶ。
retain前lifetimeは
`min(message deadline, availability expiry, checked(first_admit_ms + 30000))`である。
この3値は同じtrusted Clock epochである場合だけ比較し、message deadline、admission sample、
selected availabilityのepochが1つでも異なればTX 0でfenceする。
初回PREPAREDを作るFULL transactionで、この値をFBA1
`retry_lifetime_clock_epoch_id/retry_expires_at_ms`へimmutable copy-ownする。Commandでは
timer epochをmessage deadline epochと一致させ、EventFact/no-deadlineではattempt admission時の
trusted Clock epochを使う。retention clock/retention-untilとは別fieldであり、restartや
WOULD_BLOCK後にfirst-admit時刻を取り直さない。temporary/uncertain sample、epoch mismatch、
checked overflowではstart/cancel retryをarmせずTX 0でfenceする。
RETRYABLE_NO_ACCEPTをrestartで読んだ場合、trusted current epochが保存値と一致し
`now_ms < retry_expires_at_ms`ならstateをそのまま保持して上位からのexact retryだけを待つ。
`now_ms >= retry_expires_at_ms`ならprovider start 0でCLOSEDへFULL replacementする。epoch不一致/
clock不明はexpiredでないと推測せずFENCED_UNKNOWNへFULL replacementする。
retain後はprovider `poll_send`を1 item/stepあたり最大1回行い、同deadline到達時に
`cancel_send`をexactly 1回呼ぶ。cancelがLOST_UNKNOWNまたはinvalidならattemptをunknown fenceへ
閉じ、上位automatic duplicate 0。poll/cancel call数はstep work budget、startはouter Bearer send
budgetを消費する。

outer receiveはFabric queueから1 messageだけを返す。`step`はshared queue slot、1925-byte owned
buffer、2048-byte decode scratchを先に予約できる場合だけlink `receive_next`を呼ぶ。OK packetは
call中にmagic/version/length/CRC、6-kind matrix、policy/authority/Attachment/attempt bindingを
検証して全variable bytesをFabric bufferへcopyし、link receive tokenをrelease exactly 1回する。
APPLICATION/CANCEL_REQUESTは対応FBT1をFULL commitしてから、reverse kindは保存済みFBA1/FBT1と
bit-exact照合してからFoundation messageへprojectする。commit unknownはprovider tokenをreleaseして
outer LOST_UNKNOWN fence、invalid/unknown/missing contextはCORRUPTで、どちらもRuntime callback/
Receipt/reducer input 0である。valid projectionだけをbounded receive queueへpublishする。

outer `receive_next`はqueue emptyならEMPTY、valid先頭ならOK+Fabric-owned viewsを返す。
同時outer receive loanはexact 1個で、次のreceiveはloan releaseまでWOULD_BLOCKである。
`release_received`がそのloanをexactly 1回consumeし、custody/Receipt/effect evidenceを生成しない。
link UNAVAILABLE/WOULD_BLOCK/EMPTYはqueue mutation 0、link LOST_UNKNOWN/CORRUPT/unknown shapeは
outer同名statusまたはCORRUPTへfail closedし、non-OK poison tokenはrelease後CORRUPTとする。

## Deterministic path selectionとrace

Fabric attempt admissionは次の順で1回のimmutable FBM1/FBR1/FBP1/FBC1 snapshotを作る。

1. CRC-valid FBM1 exact 1、outer available=1を確認する。missing/duplicate/unknown state、
   outer unavailableはselectionを行わない。
2. 各policy IDについてCRC/digest-valid revisionを列挙し、gap/rollbackなくstrict +1でつながる
   最大revisionをcurrentとする。各IDのold retained revisionをresolver候補にしない。そのcurrentの
   service identity/family/direction/traffic class/scope selectorにexact matchするpolicy IDを
   列挙する。0件はUNAVAILABLE、2 ID以上または同一ID/revisionのdigest conflictはCORRUPTである。
3. policy ID/revision/digestをpinする。current revision更新を進行attemptへ適用しない。
4. policyの先頭`candidate_count` entryだけを列挙し、instance IDでFBR1へexact 1件joinする。
   missingはineligible、duplicate/key-payload conflictはCORRUPTである。
5. policy selectorからendpoint runtimeを導出し、service digest/family/direction/traffic/
   selector/endpoint/target/policy identityがexact一致するFBC1へexact 1件joinする。TARGET_RUNTIME
   ではFBC1 endpointがFoundation target runtime、SOURCE_RUNTIMEではsource runtimeと一致しなければ
   ineligible/CORRUPTであり、targetをsourceとして代用しない。BOUND_REQUIREDではBOUNDだけ、
   ABSENT_ALLOWEDでは明示ABSENTまたはBOUNDだけを許し、record 0件をABSENTへ補わない。
6. join ambiguity（FBR1 exact-1、FBC1 exact-1）の後、候補ごとに次の**固定 hard-filter 順**で
   評価する（順序変更禁止。複数failure同時でもprimary rejectionは先頭1件のみ）:
   1. FBR1 lifecycle ACTIVE
   2. send direction mask
   3. absolute NFL1 structural length `packet_bytes ∈ [587, 1925]`
      （underflow / overflow。codec KATとは独立のadmission gate）
   4. policy minimum packet bytes（structural floorとは別。`packet_bytes < policy.minimum`）
   5. packet MTU（`packet_bytes > registry.maximum_packet_bytes`）
   6. transfer MTU（`transfer_bytes > registry.maximum_transfer_bytes`）
   7. policy latency ceiling（`registry.latency_class > policy.maximum_latency_class`）
   8. policy cost ceiling（`registry.cost_class > policy.maximum_cost_class`）
   9. deadline guard
   10. retry lifetime clock epoch
   11. reservation units/capacity
   12. required generic feature
   13. sleep/energy
   14. security
   15. custody
   16. evidence
   17. peer NFL1/capability
   18. authenticated peer
   19. Attachment authority/binding
   20. attestation clock epoch/expiry
   21. availability clock epoch/state/expiry
   22. FBC1 authority state/clock epoch/lease
   23. RF compliance/TxPermit
   24. accepted compact RF mapping
   FBM1 outer availabilityはstep 1のpreconditionであり、本hard-filter chainの外である。
   各clock gateは保存epochとtrusted current epochがbit-exactかつ
   `now_ms < exclusive_expiry`だけを通す。
7. eligible candidateを次のunsigned tupleで昇順sortする。

```text
(policy_candidate.rank_u16,
 descriptor.latency_class_u16,
 descriptor.cost_class_u16,
 instance_id[16] lexicographic unsigned bytes)
```

priorityはpolicy candidate rankへadmission前にmaterializeし、current metric、thread timing、
registration order、pointer、map iteration、newer availability epochをtie-breakにしない。
deadline/reservation/security/complianceはeligibilityであってsoft sortではない。
複数hard failureが同時に成立する場合は上記順の最初をprimary rejectionとし、後段の
authority/permit/providerをcallしない。候補ごとの全診断理由を列挙してもouter statusとside effectは
primary rejectionで決める。
先頭を選び、Fabric-wide non-zero `path_selection_epoch`をchecked +1してFBA1へ保存する。
wrap時は新attempt admissionをCORRUPT/fail closedとする。

reservation usageは同じselected instanceを参照するstate
`PREPARED/LINK_RETAINED`のFBA1がpinしたpolicy candidate `reservation_units`のchecked sumで、
`sum + new_units <= FBR1.reservation_capacity`だけをeligibleとする。reservation IDは追加entropyを
使わずattempt IDとbit-exact同一で、FBA1 PREPAREDの同じFULL commitがreservation取得である。
state RETRYABLE_NO_ACCEPT/CLOSED/FENCED_UNKNOWN/DRAINEDはnew reservation usageへ数えないが
record自体はretentionまで残す。

selection時のregistry record revision/digest、descriptor/security attestation/peer/Attachment/
availability epoch/expiryをFBA1へcopy-ownする。outer ownership transfer直前にcurrent instance ID、
lifecycle ACTIVE、availability epoch/state、hard expiry、revocation、authority fence、TxPermitを
再検証する。ここでepochが変わればqueue/provider retention 0、same attempt reselect 0でFBA1
CLOSED replacementを先に確定し、UNAVAILABLEまたはDENIEDを返す。provider `start_send`直前にも
同じouter call内でhard gateを再検証し、changeならprovider call 0で同じCLOSED pathを使う。
provider RETAINED後のchangeはouter ACCEPTEDを遡及変更せずtokenの
terminalまで追跡する。別path retryは上位Runtimeが同じtransaction IDと**新しいattempt ID**を
発行した場合だけ新FBA1を作る。

physical RF candidateはdescriptorのregulatory binding、current TxPermit、Accepted 30章の
R5/R2/R1/L1 sole-authority chainをすべて満たす場合だけeligibleである。Fabric availability、
policy rank、reservation、Wi-Fi permit扱いをRF authorizationへ代用しない。Fabric/Wi-Fi/RF
adapterがPermit issue/consume、clock sample、radio edgeの新しいauthorityになってはならない。
NFL1↔NRW1 mapping未Acceptedのため、RF candidateへNFL1 packetを渡す経路自体を
`UNSUPPORTED/TX 0`とする。

## Bounded resource profile 1

| Resource | Exact limit | Exhaustion |
| --- | ---: | --- |
| caller workspace | 198,656 bytes / `max_align_t` | create `CAPACITY`、partial handle 0 |
| registered instances | 16（same kind可） | 17件目`CAPACITY` |
| policies / candidates per policy | 64 / 8 | mutation 0で`CAPACITY` |
| authority bindings | 64 | 65件目またはambiguous lookupを`CAPACITY/CORRUPT` |
| active+retained FBA1 attempts | 64 | new outer ownership 0、WOULD_BLOCK |
| ingress trigger contexts | 64 | ingress projection/callback 0、provider buffer release後CORRUPT |
| shared send+receive queue / per-link retained | 32 / 8 packets | ownership/pull前WOULD_BLOCK |
| queued NFL1 owned bytes | 61,600 = 32 × 1,925 | overrun/heap fallback 0 |
| encode/decode scratch | 2 × 2,048 = 4,096 bytes | operation side effect 0 |
| live timers | 64 | ownership前WOULD_BLOCK |
| start calls | 1 / outer send invocation | provider no-retainはsame callでexact status、internal delayed start 0 |
| step work | callerの`1..64`、1 vtable/storage/timer transition=1 | budget到達でreturn、same tick spin 0 |
| durable committed logical | 273 entries / 137,940 Storage CU bytes | evictionせずnew admission 0 |
| provider FULL staging reservation | 546 entries / 275,880 Storage CU bytes（committedの2倍） | create/open拒否、best effort開始0 |

active/retained attempt、DRAINING instance、参照中policy/trigger contextを容量確保のためevictしない。
terminal attempt/triggerは、対応private releaseがnon-zeroのRuntime terminal release tokenを
FULL保存した後だけGC対象になれる。FBA1はDRAINEDかつprovider token 0を必須とし、record内
retention clock epochと、permit clock authorityを再利用する`retry_lifetime_clock_epoch_id`を
照合する。trusted current clockを取得でき、permit epochがcurrentと異なる場合、またはpermit
epochとretention epochがともにcurrentと一致して
`now_ms >= max(retention_until_ms, permit_expires_at_ms)`の場合だけ削除できる。FBT1はterminal
release tokenがnon-zero、trusted current clockとretention epochが一致し、
`now_ms >= retention_until_ms`の場合だけ削除できる。clock不明、必要なepoch不一致、期限前では
保持し、policy/authority参照もdurable eraseの確定までは解除しない。GCはFBA1/FBT1それぞれの
固定64-slot round-robin cursorとinstance-localなkind選択を使い、片方をstarveさせず、1回の
step invocationにつき両kind合計で最大1 erase、1 attempted erase=1 workである。CU-NEWは
削除済みとしてslotを解放し、CU-OLDは保持、partial/third/errorはfail-closedでsurfacingする。
既存field/parameter名`runtime_terminal_revision`はlegacy nameであり、Composition Profile 1では
ADR-0032のterminal release tokenを保存する。Runtimeのmutable `record_revision`または
EventFact `spool_revision`を意味しない。
metrics/diagnosticsはinstanceごと固定1 slotで上書きし、
payload/secret/socket/OS error textを保持しない。provider自身のsocket/TLS/RF resource上限は
descriptor外のport profileにexact記載し、unknown/unbounded providerをregisterしない。

198,656-byte workspace partitionは
`NFL1 queue 61,952 + codec scratch 4,096 + registry objects 11,136 +
policy slots 8,704 + authority slots 20,480 + attempt slots 52,224
(64 × 816) + trigger slots 15,360 + receive queue 24,064 + timers 128 +
registration/metrics 128 + control 384`でexactである。
regionを相互貸与せず、unused regionを別limit超過の救済に使わない。
policy/authority regionはfull durable valueの複製ではなく、fixed key/revision/digest/lookup indexだけを
保持する。selection/snapshotはworkspace内の712-byte value ceilingでexact 1 recordずつ
copyしてCRC/canonical digestを再検証し、attemptに必要なimmutable fieldだけをFBA1 slotへcopy-ownする。
Storage iterator/value pointerをreturn後または別Port callまでborrowせず、同時に2 full valueを要求しない。

## Fabric storage schema 1

### Namespace、common envelope、keys

FabricはFoundation Runtime store、30章radio-security storeと別のexact namespace
`ninlil.fabric.v1`を同じStorage Port contractでexclusive openする。Foundation schema 1、
ESP physical format 4、30章recordを再解釈・共有しない。socket、pointer、fd、TLS object、
volatile metric、TxPermit pointer/raw host structは保存しない。call-scoped permitのcanonical
ID/expiry/claimと、そのclock authorityを兼ねるretry lifetime epochだけをFBA1へ保存する。
Accepted 30章が記録する現ESP port `max_namespaces=2`へ3個目を暗黙追加せず、既存2 namespaceの
どちらにもFabric recordを混在させない。そのprofileではFabric featureをUNSUPPORTEDのままにし、
ESPで有効化するにはnamespace capacity/profileを別reviewで増やしたtarget evidenceが必要である。

全integerはunsigned big-endian。全valueは次の24-byte common envelopeを持つ。

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | record別magic `FBM1/FBR1/FBP1/FBC1/FBA1/FBT1` |
| 4 | 2 | storage schema = 1 |
| 6 | 2 | header length = 24 |
| 8 | 4 | exact total value length |
| 12 | 8 | non-zero record revision |
| 20 | 4 | CRC32C（NFL1と同じ式、計算時zero） |

trailing、unknown magic/schema、length不一致、revision 0、CRC不一致、reserved non-zeroをrejectする。
keyは次のexact bytesで、host struct/padding/NULを含めない。

| Record | Exact key | Key bytes | Value bytes | Maximum count |
| --- | --- | ---: | ---: | ---: |
| meta | ASCII `FBM1` | 4 | 64 | 1 |
| registry | ASCII `FBR1` + instance ID[16] | 20 | 372 | 16 |
| policy revision | ASCII `FBP1` + policy ID[16] + revision u64 | 28 | 352 | 64 |
| authority binding | ASCII `FBC1` + binding ID[16] | 20 | 512 | 64 |
| attempt | ASCII `FBA1` + transaction ID[16] + attempt ID[16] + message kind u32 + response slot u32 + Foundation message digest[32] | 76 | 712 | 64 |
| ingress trigger | ASCII `FBT1` + transaction ID[16] + triggering attempt ID[16] + kind u32 | 40 | 248 | 64 |

Foundation Storage CUは1 recordごとに`16 + key bytes + value bytes`である。したがってmaximumは
`1+16+64+64+64+64=273 entries`、
`Σ(key+value)=133,572 bytes`、overhead `273×16=4,368`、
合計`137,940 bytes`である。FULL stagingはこのexact 2倍の546 entries / 275,880 bytesを
create時に同一namespace capacity snapshotで要求する。

maximum countはactiveだけでなくretained/old revisionを含むnamespace内の総record数である。openは
fresh READ_ONLY snapshotをkey unsigned-lexicographic順に全scanする。受理する形は
**全record 0のfresh candidate**または**FBM1 exact 1を含む完全なexisting snapshot**だけである。
existingでは各prefix count、key/value identity一致、duplicate/out-of-order、value ceiling 712を
検証してrollback OK後だけregistryをpublishする。65件目等をtruncate/evictしない。

全record 0の場合はREAD_ONLYをrollback OKで閉じ、fresh READ_WRITE transactionを開始して
namespaceを再び全scanし、依然として全record 0であることを確認する。同じtransactionで
revision 1のcanonical FBM1だけをputして`FULL` commitする。definite failureではpublish 0、
`COMMIT_UNKNOWN`ではnamespaceをclose/reopenし、fresh READ_ONLYで`ABSENT`またはexact new FBM1だけを
分類する。第三値/他record/mixedはCORRUPT、いずれの分類でもそのcreate callは
`COMMIT_UNKNOWN`を返し、Bearer/provider open、registry publishは0である。commit OK時も一度
close/reopenし、通常existing scanを通過してからだけcreateを続行する。READ_ONLY→READ_WRITE間に
1 recordでも現れた場合は同時初期化競合としてmutation 0/CORRUPTとし、既存値を上書きしない。
既存snapshotがcount超過ならCORRUPT、新規insertが上限に達した場合はmutation 0のCAPACITYである。
commit OK後のreopenでもFBM1 exact 1を含む通常existing snapshotだけを受理する。
FBM1なし、duplicate key、unsigned-lexicographic out-of-order、いずれかのprefix count超過は
publish/provider open 0のCORRUPTであり、truncate、sortし直し、最古record evictionをしない。

### FBR1 registry payload（348 bytes）

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 16 | instance ID |
| 16 / 20 / 24 | 4 each | link kind / direction mask / capability flags |
| 28 / 36 | 8 / 32 | descriptor revision / descriptor digest |
| 68 / 84 / 88 | 16 / 4 / 32 | security profile ID / capability flags / binding digest |
| 120 / 128 / 144 / 152 | 8 / 16 / 8 / 32 | attestation epoch / clock epoch ID / exclusive expiry ms / attestation digest |
| 184 / 200 / 216 | 16 / 16 / 32 | authenticated peer Runtime / Attachment authority / binding digest |
| 248 / 252 | 4 / 4 | maximum packet / maximum transfer |
| 256 / 258 / 260 / 262 | 2 each | latency / cost / reservation capacity / reserved=0 |
| 264 / 272 | 8 / 16 | availability epoch / clock epoch ID |
| 288 / 289 / 290 | 1 / 1 / 2 | state 0..1 / lifecycle ACTIVE=1,DRAINING=2 / reserved=0 |
| 292 | 8 | availability exclusive expiry ms |
| 300 / 302 / 304 | 2 / 2 / 4 | peer NFL1 version=1 / reserved=0 / peer Fabric capability flags |
| 308 / 316 | 8 / 32 | configuration revision / configuration digest |

same instance IDではoffset 16..263と300..347をimmutableとし、availability更新はrecord revisionと
availability epochをともにstrict +1してoffset 264..299だけ置換する。same epoch exact再読は
idempotent、same/older epoch conflict、digest conflict、duplicate keyはCORRUPTである。provider
`state`でnew epochを観測しても、このFBR1 replacementのFULL commit OKより前はselectionへ使わない。
commit definite failureはprior durable state、COMMIT_UNKNOWNはinstanceをineligible/fencedにして
read-classify前のselection/TX 0である。
FBA1がpinするfull FBR1 digestは
`SHA-256(ASCII("NINLIL-FABRIC-REGISTRY-RECORD-V1") || exact_key || exact_value)`である。

### FBP1 policy payload（328 bytes）

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 / 16 / 24 | 16 / 8 / 32 | policy ID / revision / canonical digest |
| 56 | 32 | service identity canonical digest |
| 88 / 92 | 4 / 4 | family / direction |
| 96 / 98 | 2 / 2 | traffic class / scope selector (`SOURCE_RUNTIME=1`,`TARGET_RUNTIME=2`) |
| 100 / 104 | 4 / 4 | required capability / required security flags |
| 108 / 110 / 112 | 2 / 2 / 4 | maximum latency / maximum cost / minimum packet bytes |
| 116 / 117 | 1 / 3 | authority mode (`ABSENT_ALLOWED=0`,`BOUND_REQUIRED=1`) / reserved=0 |
| 120 | 8 | deadline guard ms |
| 128 / 130 / 132 | 2 / 2 / 4 | candidate count 1..8 / reserved=0 / reserved=0 |
| 136 | 8 × 24 | fixed candidate entries |

candidate entryは`instance ID[16] | rank u16 | flags u16(=0) | reservation units u16 |
reserved u16(=0)`。count後のentryはall-zeroである。canonical digest計算時だけoffset 24..55をzeroにし、
前述tagged SHA-256を使う。policy removeはcurrentでなく、FBA1/FBT1参照0かつretention済みのrevision
だけ許す。resolverはpolicy IDごとの最大revisionだけをcurrentとし、old retained revisionを
match数へ入れない。revision chainのgap、同一ID/revisionの複数value、current rollbackはCORRUPTである。
policy/service digest/候補instanceはnon-zero、candidate instanceはpolicy内unique、
family/direction/scope selector/authority modeはclosed known value、required flagsは上記known mask内、
candidate countは1..8、各reservation unitsは1以上である。違反inputはINVALID_ARGUMENT、
durable row違反はCORRUPTである。未登録instanceを候補に保持できるがselectionではineligibleとする。

### FBC1 authority/assignment payload（488 bytes）

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 / 16 | 16 / 32 | binding ID / service identity digest |
| 48 / 52 / 56 / 58 | 4 / 4 / 2 / 2 | family / direction / traffic class / scope selector |
| 60 / 76 / 92 | 16 / 16 / 16 | endpoint runtime / target runtime / target application |
| 108 / 124 / 132 | 16 / 8 / 32 | policy ID / revision / digest |
| 164 / 168 / 184 / 192 / 196 | 4 / 16 / 8 / 4 / 4 | authority state / ID / term / assignment epoch / reserved=0 |
| 200 / 216 / 248 | 16 / 32 / 200 | owner scope / full owner tuple digest / canonical owner tuple |
| 448 / 464 / 472 / 480 | 16 / 8 / 8 / 8 | authority clock epoch / exclusive lease expiry / assignment revision / reserved=0 |

key binding IDとpayload offset 0はbit-exact一致する。authority stateはABSENT=0、BOUND=1だけで、
ABSENT/BOUND zero/non-zero matrix、policy/endpoint lookup、revision/lease規則はprivate API節のexact
contractを使う。FBC1 replacementはcommon record revisionとassignment revisionをともにstrict +1する。
definite failureはold exact、COMMIT_UNKNOWNはold/new/CRC-valid thirdをread-classifyし、分類前は
authority lookup/send 0である。
scope selectorはSOURCE_RUNTIME=1またはTARGET_RUNTIME=2だけで、FBC1と参照FBP1でbit-exact一致する。
SOURCE_RUNTIMEではoffset 60 endpointがFoundation source runtime、TARGET_RUNTIMEではFoundation
target runtimeと一致し、どちらでもoffset 76はconcrete target runtimeである。unknown selector、
selectorが選ぶendpointとの不一致、service/family/direction/traffic mismatchはCRCを再計算した
single-field durable mutationでもCORRUPT/TX 0とする。

### FBA1 attempt payload（688 bytes）

offset 44のFoundation message digestは、生成済みNFL1のcopyを作り、CRC offset 12..15、
authority group offset 272..299、Fabric route enrichment offset 484..569をzeroにしたexact
`total_length` bytesを`M`として、
`SHA-256(ASCII("NINLIL-FABRIC-FOUNDATION-MESSAGE-V1") || M)`で計算する。これにより同じFoundation
messageをpath/authority enrichmentと独立に比較する。host struct/pointer/paddingは入力しない。

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 / 16 | 16 / 16 | transaction / attempt ID |
| 32 / 36 / 40 / 44 | 4 / 4 / 4 / 32 | message kind / response slot / state / canonical Foundation message digest |
| 76 / 92 / 100 | 16 / 8 / 32 | policy ID / revision / digest |
| 132 / 148 / 156 | 16 / 8 / 4 | selected path / selection epoch / route flags=0 |
| 160 / 164 / 180 / 188 | 4 / 16 / 8 / 4 | authority state / ID / term / assignment epoch |
| 192 / 208 | 16 / 32 | owner scope / canonical owner tuple digest snapshot |
| 240 / 248 | 8 / 32 | registry record revision / full FBR1 digest |
| 280 | 32 | descriptor digest |
| 312 / 328 / 336 / 352 / 384 | 16 / 8 / 16 / 32 / 8 | security profile / attestation epoch / clock epoch / digest / expiry |
| 392 / 408 / 424 | 16 / 16 / 32 | peer Runtime / Attachment authority / binding digest |
| 456 / 464 / 480 / 481 / 488 | 8 / 16 / 1 / 7 / 8 | availability epoch / clock epoch / state / reserved=0 / expiry |
| 496 / 512 / 528 | 16 / 16 / 8 | reservation ID / deadline clock epoch / deadline ms |
| 536 / 540 | 4 / 32 | NFL1 length / SHA-256 |
| 572 / 588 | 16 / 8 | retention clock epoch / exclusive retention-until ms |
| 596 / 612 | 16 / 8 | retry lifetime clock epoch / exclusive retry-expires-at ms |
| 620 / 652 | 32 / 8 | local dispatch ID / Runtime terminal revision（release前0、release後non-zero） |
| 660 / 676 / 684 | 16 / 8 / 4 | permit ID / exclusive permit-expires-at ms / permit claim state（CLEAR=0、CLAIMED=1） |

state catalogは`PREPARED=1, LINK_RETAINED=2, RETRYABLE_NO_ACCEPT=3, CLOSED=4,
FENCED_UNKNOWN=5, DRAINED=6`だけ。transitionは値replacementのrecord revision strict +1で、
identity/policy/path/message/encoded digest snapshotを変更しない。
`retry_lifetime_clock_epoch_id`はpermitのclock authorityでもあり、non-zero必須である。
permit ID/expiryもnon-zero、claim stateはclosed set 0/1だけである。LINK_RETAINEDはCLAIMED、
RETRYABLE_NO_ACCEPTはCLEARを必須とし、一度CLAIMEDになったrowはuncertain/FENCED/DRAINEDで
消去しない。
same exact FBA1 keyでstate/common record revision/terminal revision/claim state以外の差は
CORRUPT/TX 0である。ただしRETRYABLE_NO_ACCEPTからのexact retryだけは、fresh
`(clock_epoch_id, permit_id)`とexpiryへの置換、state PREPARED、claim CLAIMEDを同じFULLで行う。
keyのtransaction/attempt/kind/response slot/digestは
payloadとbit-exact一致し、offset 620はtagged local-dispatch digestと一致する。APPLICATION/
CANCEL_REQUESTの同じ`{transaction,attempt,kind}`に2 message digestを見た場合はCORRUPTだが、
Foundation規則でvalidな別reverse kind/progressive Receiptは別keyとして共存できる。
PREPARED後のpre-start hard race/denyはprovider call 0のままCLOSED、provider WOULD_BLOCKは
CLAIMEDからRETRYABLE_NO_ACCEPT+CLEARへ1 FULL replacementし、そのcommit OKまたはCU-NEW分類後だけ
reservation/tentative queue/timerを
releaseする。release replacementのdefinite failureはinstance/dispatch CORRUPT fence、
COMMIT_UNKNOWNはfresh read-classifyしてouter LOST_UNKNOWNとする。LINK_RETAINED後はprovider terminalで
CLOSEDへ進みCLAIMEDを保持する。RETRYABLE_NO_ACCEPTのexact retryは保存clock epoch一致かつexclusive expiry前、
同じcaller message、FBC1 lookup、policy/path snapshotがbit-exactの場合だけPREPAREDへ進め、
期限到達はCLOSED、clock不明/epoch不一致はFENCED_UNKNOWNへ進む。
private dispatch_releaseがPREPAREDを観測した場合もprovider start 0でまずCLOSEDへFULL replacementし、
そのcommit OK後にnon-zero terminal revisionを持つDRAINEDへ別FULL replacementする。
CLOSED/FENCED_UNKNOWNはprivate dispatch_releaseのnon-zero terminal revisionでDRAINEDへ進む。各transitionの
OLD/NEW/third/mixed分類前にsame dispatch provider start/reselect/reencodeを行わない。
process restartでPREPAREDまたはLINK_RETAINEDを読んだ場合は、volatile queue/provider tokenを
復元せずFENCED_UNKNOWNへFULL replacementする。RETRYABLE_NO_ACCEPTだけは上記durable lifetime規則で
expiry前保持またはexpiry時CLOSEDに分類できる。全transitionはactual old/new bytesをKATにし、
CLOSED replacementとrestart fence replacementのCOMMIT_UNKNOWNはOLD/NEW/CRC-valid thirdを
別vectorで固定する。

FBA1のregistry revision/full digestはselection時点のhistorical FBR1 snapshotであり、
FBA1 state transition、Runtime release、または後続availability更新で書き換えない。
schema 1はinstance IDごとにcurrent FBR1を1行だけ保持するため、restart joinでは次の2形だけを
canonicalとする。current FBR1 record revisionがFBA1 pinと同じ場合は従来どおりfull digestを
bit-exact一致させる。current revisionがpinより新しい場合は、descriptor digestとavailability
clock epochがbit-exact一致し、current availability epochもpinより新しく、かつ
`current_record_revision - pinned_record_revision ==
current_availability_epoch - pinned_availability_epoch`であるstrict availability successorだけを
候補とする。そのcurrent FBR1のimmutable fieldsと、FBA1に保存した旧availability
epoch/clock epoch/state/expiryおよびselection時のlifecycle ACTIVEから旧FBR1 valueを再構成し、
FBA1のhistorical full digestとbit-exact一致した場合だけsuccessorとして許す。
revision/availabilityのrollback、片方だけのadvance、同revisionでのdigest不一致、旧value再構成の
digest不一致、descriptor digest不一致はCORRUPTである。このsuccessor規則は過去のselection
authorityをcurrent availabilityへ読み替えず、retained FBA1のretry/reselect/provider replayを
許可しない。

### FBT1 triggerとFBM1 migration payload

FBT1 224-byte payloadは
`transaction[16] @0, triggering_attempt[16] @16, triggering_kind u32 @32,
authority_state u32 @36, endpoint_runtime[16] @40, owner_scope[16] @56,
authority_id[16] @72, authority_term u64 @88, assignment_epoch u32 @96,
reserved u32=0 @100, owner_tuple_digest[32] @104, policy_id[16] @136,
policy_revision u64 @152, policy_digest[32] @160, retention_clock_epoch[16] @192,
retention_until_ms u64 @208, Runtime terminal revision u64 @216`である。terminal revisionは
trigger_release前0、release後non-zeroである。APPLICATION/CANCEL_REQUEST ingressをRuntimeへpublishする前の
同じFULL transactionで作り、reverse 4 kindのenrichmentに使う。

FBM1 40-byte payloadは`source_schema u16 @0, target_schema u16 @2,
migration_state u16 @4, reserved u16=0 @6, migration_generation u64 @8,
rollback_floor_generation u64 @16, outer_availability_epoch u64 @24,
outer_available u32 @32, reserved u32=0 @36`。schema 1初回作成はsource=target=1、
state CLEAN=1、generation=1、rollback floor=0、outer availability epoch=1/available=0である。
outer available 0↔1または以前blockedだったshared queueに実capacityが戻るtransitionは、
FBM1 record revisionとouter availability epochをstrict +1する同じFULL replacementでpublishする。
poll、send成功、same state、restartだけではincrementせず、wrap/rollback/same epoch conflictは
outer unavailable/CORRUPTである。v1にpredecessor migrationはなく、
空namespaceへFBM1を作るfresh adoptionだけを許す。FBM1なしで他recordあり、unknown schema、
state MIGRATING=2、source/target不一致を見たv1 binaryはmutation 0でUNSUPPORTED/CORRUPT。
将来migrationは新schema ADRでsource/target/stateと全write-point KATを追加するまで行わない。

### FULL、COMMIT_UNKNOWN、retention

全mutationはFoundation Storageの`FULL` transactionを使う。packet-link `start_send`はFBA1
PREPARED commit OKより前に0回である。commitが`COMMIT_UNKNOWN`ならtransaction handleはconsumedし、
Fabric namespaceをclose/reopenしてfresh READ_ONLYでexact keyとFBM1を再読する。候補は
`OLD exact / NEW exact / create時ABSENT`だけで、CRC-valid第三値、同一FULL groupのold/new混在、
duplicate keyはCORRUPTである。OLD/NEW/ABSENT分類のouter callはLOST_UNKNOWN、CRC-valid
third/mixed/duplicateはCORRUPTで、いずれもprovider start、
reencode、reselect、same-attempt retry 0。NEWならFBA1をFENCED_UNKNOWNとして保持、OLD/ABSENTも
upperがLOST_UNKNOWNを既に観測したattemptを再送しない。次のnew attemptだけ通常selectionへ進める。
ただしintended NEW自体がCLOSEDまたはFENCED_UNKNOWNという安全終端replacementなら、NEW分類後に
そのexact stateを保持し、追加のstate書換えを要求しない。PREPARED/LINK_RETAINEDをpublishし得る
NEWだけはfresh reconcileでFENCED_UNKNOWNへ進める。

permit claim replacementも同じactual OLD/NEW bytesで分類する。CLEAR→CLAIMEDのCUは分類にかかわらず
provider start 0でLOST_UNKNOWNとし、NEWならCLAIMEDを保持する。provider definite non-accept後の
`{state, claim=CLEAR}` replacementはNEWだけがexact intended resultで、元の
WOULD_BLOCK/UNAVAILABLE/DENIEDへ進める。OLD、value prefixなどpartial、CRC-valid thirdは
CLAIMEDを消去したと推測せずLOST_UNKNOWN/fenceとする。RETAINED、provider shape不明、
provider side effectがuncertainな経路でCLEARへ進めない。

registry+meta、policy+meta、authority+meta、attempt+triggerなど複数keyを同じFULL transactionで変える場合は
all-old/all-newだけを受理する。証拠なしにselection/availability/owner binding成功を生成しない。
active/retained FBA1が参照するFBR1/FBP1/FBC1/FBT1を削除せず、availability epochをrestart前へ
巻き戻さない。retention/GCはbounded resource表のexact規則だけで、capacity不足時にoldest active、
unknown fence、policy revisionを自動evictしない。
process restartでvolatile queue/provider tokenを失ったFBA1
`PREPARED/LINK_RETAINED`は、recordだけからpacket-link sendを再構成せず
FENCED_UNKNOWNへFULL transitionする。そのtransitionのCOMMIT_UNKNOWNも同じread-classifyを通し、
same attemptのprovider start/replay/reselectは0である。上位のtransaction/Receipt/dedupe contractだけが
same transaction/new attemptを決める。

## Vector authorityとmixed version

独立oracle [tools/fabric_bearer_spec_vector_gen.py](../../tools/fabric_bearer_spec_vector_gen.py) と
[spec/vectors/fabric-bearer-spec-v1.json](../../spec/vectors/fabric-bearer-spec-v1.json) を
candidate authorityとする。production codec/helperをimportせず、`--write`と`--check`が
byte-identical JSONを作る。[tools/fabric_bearer_spec_gate.py](../../tools/fabric_bearer_spec_gate.py)
はgeneratorをimportせずPythonでselection/recordを再計算し、別実装のNode oracleも起動する。

vectorは全6 kindの587-byte minimum enrichment/projection、明示ABSENT authority、
APPLICATION 1797-byte semantic max、
RECEIPT evidence max、1925-byte structural-but-semantic-invalid、586/1926/2049 length、CRC、
unknown version/kind/flags/closed enum/digest algorithm、mixed authority、kind matrix mutation、
SOURCE_RUNTIME/TARGET_RUNTIME selectorとendpoint mismatch、same-kind 2 instance選択、
stable-ID tie-break、actual FBM1/FBR1/FBP1/FBC1 joinを使うsingle-difference全hard eligibility
filter/precedence、availability race、RF permit deny、same-call
provider WOULD_BLOCK/partial TLS、FBR1/FBP1/FBC1/FBA1/FBT1/FBM1 KAT、progressive Receiptと
CANCEL_REQUESTのdispatch非衝突、FBA1全state transitionのold/new actual bytes、
CRC/schema/digest/key-identity mutation、actual record bytesを使う
fresh adoption/commit-OK reopen existing/malformed existingとCOMMIT_UNKNOWN
old/new/absent/third/mixed groupを含む。Python generatorとは実装を共有しないNode/Python gateが
record envelope/CRC/SHA、canonical digest、selection join/filter、single-difference mutation、
state/CU actual bytesを再計算し、gate自身のmutation self-testも通す。

mixed versionは`local=1/peer=1`のexact NFL1だけを許す。peer 0/2、unknown version/capability、
NFL1非対応peerはattach/packet admissionをUNSUPPORTEDで拒否する。LAB raw struct、field drop、
authority/path zero補完、silent downgrade/upgrade fallbackは0回である。legacy packet-linkに
descriptorがない場合も不明能力を推測せずUNSUPPORTEDとする。

## Acceptance

### SPEC_ACCEPTED（実装開始を許可する設計gate）

次をすべて満たした時点で本ADRを設計決定としてAcceptedにできる。これはFabric実装済み、
target対応、production supportを意味しない。

1. NFL1 exact KAT（各kindのminimum-valid/zero-optional-fields、全field、最大長）とCRC32C
   cross-language oracle
2. endian/padding/pointer非依存をLP64/ILP32、GCC/Clang、Linux/macOSで証明
3. truncated、trailing、overflow、unknown version/enum/flag、CRC mutationを全reject
4. encode borrow、decode copy-own、buffer-too-small副作用0、clear zeroization
5. private/default-OFF Fabric API candidateの関数signature、opaque handle/workspace lifecycle、borrow/copy ownership、
   thread/reentrancy、status precedence、packet-link callback contractをexactに固定
6. path policy/authority registry、attempt dispatch/ingress trigger recordのcanonical key/value、
   byte layout、CRC、maximum count、retention、COMMIT_UNKNOWN recoveryをKAT化
7. Runtime admissionとFabric attempt admissionの境界、旧`ninlil_bearer_message_t`からNFL1への
   enrichment、NFL1から旧messageへのlossless projectionを全6 kindで証明
8. deterministic selectionのeligibility、sort/tie-break、reservation、reselection、
   expiry/revocation/compliance precedenceを独立modelで固定
9. Runtime ABI golden manifest不変、既存v1 consumer compile/link、raw struct fallback 0
10. resource profile、compatibility、requirements traceability、独立reviewでP0/P1 0

2026-07-29、machine authorityの再現確認と独立review
（[review record](../reviews/2026-07-29-fabric-bearer-spec-accepted.md)）で
**P0=0 / P1=0 / P2=0**を確認し、本設計gateを閉じた。これはprivate/default-OFF
実装開始を許可するだけで、C codec、Host/ESP実装、public API、HIL、release supportの
受入ではない。

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
- 単一Bearer ABI互換は維持されるが、Fabric自身には新しいprivate source API、storage、
  test surfaceが増える。public/install APIは未割当のままである。
- compact radio logical envelopeとNFL1↔NRW1 mappingの別仕様・KATが必要になる。

## Rejected alternatives

- **`platform.h`のBearer配列化:** 既存ABIとlifecycle contractを破壊する。
- **Runtime内部へWi-Fi/LoRa分岐を直書き:** portable Coreへport/policy詳細が混入する。
- **raw C structをcanonical wire化:** pointer、padding、ABI、endian依存でportableではない。
- **NFL1 bytesをそのままNRW1へ格納:** radio airtimeと[30章](../30-r6-secure-radio-wire.md) profileを壊す。
- **availabilityだけで自動fallback:** deadline、custody、compliance downgradeを隠す。

## 非主張

本ADRは設計のみ`SPEC_ACCEPTED`である。private/default-OFF API/NFL1予約値の
実装開始は許可するが、実装完了、installed/public ABI、POSIX移行、Wi-Fi、LoRa mapping、
Relay、Multi-parent、HIL、legal、production supportを主張しない。

## Related

- [V2 Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
- [Architecture §Bearer](../01-architecture.md)
- [Versioning and Compatibility](../06-versioning-and-compatibility.md)
- [R6 Secure compact radio wire](../30-r6-secure-radio-wire.md)
- [ADR-0018: Wi-Fi Bearer](0018-wifi-bearer.md)
