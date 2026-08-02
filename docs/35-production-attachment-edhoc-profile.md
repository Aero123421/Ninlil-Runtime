# 35. Production Attachment / EDHOC profile

状態: **Proposed — specification candidate（implementation / acceptance pending）**  
ADR: [ADR-0023](adr/0023-production-attachment-edhoc-profile.md)  
前提: [3章](03-identity-and-join.md)、[30章](30-r6-secure-radio-wire.md)、
[34章](34-r7-t1c-authenticated-hop-fresh-install-owner.md)

本章はproduction用Attachmentのcarrier、wire、identity、protected install、durable
atomicity、resource/ownershipを固定する。LAB joinをproductionへ昇格せず、既存Accepted
contractを変更しない。矛盾時は既存Accepted contractを優先し、本章をProposedのまま直す。

**SEMANTIC: PA_EDHOC_METHOD3_SUITES2_AND3**  
**SEMANTIC: PA_MESSAGE4_REQUIRED_EAD_ALL_ABSENT**  
**SEMANTIC: PA_CARRIER_INDEPENDENT_NAC1**  
**SEMANTIC: PA_RECEIVER_ALLOCATED_CONTEXT_IDS**  
**SEMANTIC: PA_PROTECTED_PROPOSE_INSTALL_DUAL_CONFIRM**  
**SEMANTIC: PA_LOCAL_ATOMIC_15_KEY_FULL**  
**SEMANTIC: PA_RESTART_ALWAYS_FRESH_NO_RESUME**  
**SEMANTIC: PA_FACTORY_IDENTITY_AND_MEMBERSHIP_PRECONDITION**  
**SEMANTIC: PA_MAGIC_NAMESPACE_DISJOINT_FROM_ACCEPTED_PROFILES**  
**SEMANTIC: PA_PROPOSED_NO_IMPLEMENTATION_CLAIM**

## 1. Closed scope

含む:

- EDHOC method 3、mandatory suites 2/3、CCS/RPK + `kid`
- USB/Wi-Fi streamとcompact radioの共通Attachment record
- stateless radio cookie、bounded fragmentation/reassembly
- protected proposal/install/dual confirmation
- directional Hop/E2E secret derivation
- local exact 15-key durable FULL contract
- restart、rotation、revocation、lease、failure、resource、ownership contract
- independent Python/Node/C11 specification gates

### 1.1 Protocol magic namespace

Production Attachment v1は`NAC1`（carrier-independent record）、`NAS1`
（USB/Wi-Fi stream wrapper）、`NAR1`（compact-radio fragment）を予約する。
4-byte magicはtransport、storage、private/publicの別にかかわらずNinlil全体で一意にする。
Accepted ADR-0020が既に予約する`NPA1`（assignment page）と`NPS1`（parent set）を
Production Attachmentへ再利用することは禁止する。fixture、generator、Python/Node/C11
gateは旧衝突magicを受理してはならない。repository-wide正本は
[`spec/protocol-magic-registry-v1.json`](../spec/protocol-magic-registry-v1.json)、
実行authorityは`tools/protocol_magic_registry_gate.py`である。registryはtransportや
storageの区分をcollision exemptionにせず、duplicate、PAによる`NPA1`/`NPS1`横取り、
必須`NAC1`/`NAR1`/`NAS1`欠落をfail closedする。registry JSONはduplicate object keyを
decode前に拒否し、root/policy/domain/scan/entry/exclusionをclosed schemaとする。
`owner`、`artifact`、`status`、`authority`、exclusion reasonはregistry内のclosed value
domainからだけ選べる。

実行authorityは`cmake/`、`examples/`、`include/`、`ports/`、`src/`、`tests/`、
`tools/`のmachine sourceを固定extension集合で再帰走査する。exact 4-byte
uppercase/digit literalは、global entryまたは理由付きexplicit exclusionのどちらか
一方に必ず分類する。registry自身はscan root外なので、台帳へ書くだけでliveと見なしては
ならない。未登録literal、sourceから消えたstale entry/exclusion、entry/exclusion重複、
global collision、scan範囲の弱化をすべて拒否する。現行inventoryには少なくとも
`NLR1`、`N6TX`、`N6RX`、`N6AL`、`N6HW`を含める。

含まない:

- enrollment、Site Membership作成・変更、QRへのsecret格納
- application data、route/relay、multi-parent、custody、fragmented application message
- same-context resume、secret persistence、M5 proof
- public API、dependency adoption、implementation、HIL、field/legal/production support

## 2. Identity and policy preconditions

Production Attachment ownerは開始前に次のcopy-owned accepted claimを1つ受け取る。
raw JSON、QR、boolean、OS wall clockを直接trustしない。

| field | exact rule |
| --- | --- |
| local factory identity | state `PROVISIONED`; stable id digest non-zero |
| local authentication credential | canonical CCS + `kid` 1..8 bytes + public-key digest + opaque key reference; factory identityへbind |
| local key provider | P-256 static-DH operationだけを許可; provider generation non-zero/non-regressing; private key exportなし |
| peer authority identity | authority id 16 bytes non-zero |
| site domain | 16 bytes non-zero |
| Site Membership | state `ACTIVE`; membership epoch non-zero |
| authority term | accepted current termとequal、過去値よりnon-regressing |
| credential revision | accepted current revisionとequal |
| revocation generation | accepted current generationとequal |
| assignment epoch | accepted current assignmentとequal |
| lease | trusted clock epoch equal、`not_before <= now < expires_at` |
| suite | accepted policyが2または3のexact 1つへpin |
| carrier | accepted descriptorとcurrent instance/generationが一致 |

credential resolver keyは
`site_domain16 || authority_id16 || authority_term_u64be ||
credential_set_revision_u64be || role_u8 || kid_length_u8 || kid[1..8]`である。
CCS内RPKはP-256だけをv1で受け入れる。credential bytesはcanonical CBORの
CWT Claims Set（map claim `8 cnf` → COSE_Key）であり、ASCII疑似prefixを受理しない。
COSE_Keyは`kty=2 EC2`、`crv=1 P-256`、exact 32-byte `x`/`y`、`kid` 1..8 bytesで、
Python/Node/Cの独立decoderがmap構造と曲線/座標長を意味検証する。resolverはcaller
pointerを保持せず、unknown、ambiguous、stale、revoked、wrong roleを同じ
authentication failure classへ閉じ、秘密情報を返答差・timing差で開示しない。

peer public credential resolverとlocal static-DH key operatorは同じboolean callbackへ
畳み込まない。local credential descriptorは少なくともfactory stable-id digest、
canonical CCS bytes/digest、`kid`、P-256 public-key digest、credential-set revision、
non-zero provider generation、copy-owned opaque key referenceを固定する。operatorは
`(opaque key reference, peer P-256 public key, suite, attempt binding)`からEDHOC engineの
bounded secret workspaceへ32-byte ECDH resultを1回だけ書き、private scalarやbackend
pointerを返さない。descriptorのpublic keyとoperatorのkeyが一致することをprovider境界で
検証し、revision/generation rollback、wrong factory identity、wrong curve、unknown key、
provider reentry/partial outputはmessage送信・exporter実行0でterminal authentication
failureとする。ECDH resultはPRK導出直後にzeroizeする。

### 2.1 Constructible prerequisite claims and local-key port

PA-S0の`prerequisites` machine blockは次をexactに固定する。ただしFactory Identityと
Site Membershipの上流Accepted証拠はまだ確立していないため、
`factory_identity=UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED`、
`site_membership=UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED`であり、owner startは
`FAIL_CLOSED_NOT_READY`である。このfixtureを理由にdependency readyを主張してはならず、
ADR-0023はProposedのままにする。

- Factory Identity claim: `required_state=PROVISIONED`、32-byte stable-id digest、
  non-zero claim revision、copy-owned。
- Site Membership claim: `required_state=ACTIVE`、site/authority id、authority term、
  membership/credential/revocation/assignment revisionをcopy-ownedで持つ。
- role別local credential descriptor: factory stable-id digest、canonical CCS bytesと
  SHA-256、`kid`、P-256 public-key digest、credential-set revision、provider generation、
  opaque key referenceをcopy-ownedで持つ。initiator/responderを単一roleへ曖昧化しない。
- private local static-DH port input:
  `(opaque_key_reference, provider_generation, credential_set_revision,
  factory_stable_id_digest, local_role, peer_uncompressed_p256_public_key65,
  suite, attempt_binding_digest32)`。出力はcaller-owned bounded 32-byte workspaceへの
  exact 1 writeだけで、private scalar/backend pointerは0 bytes export、provider reentryは禁止。
- wrong identity/role/curve、public/private mismatch、credential/provider rollback、
  unknown opaque reference、reentry、partial outputはすべて
  `TERMINAL_AUTHENTICATION_FAILURE`。wire/exporter/published secret/private-key exportは0、
  32 bytesをzeroizeする。成功時もPRK導出直後に32 bytesをzeroizeする。

このstate machineはdescriptor/port contractのoracleであり、real provider KATや
cryptographic interoperabilityを主張しない。

## 3. EDHOC profile

| item | exact |
| --- | --- |
| method | 3（両者static DH authentication） |
| mandatory suites | suite 2 = `[10,-16,8,1,-7,10,-16]`; suite 3 = `[30,-16,16,1,-7,10,-16]` |
| credential | RPK in CCS, referenced by `kid` |
| message_4 | required |
| EAD | EAD_1..EAD_4すべてabsent; non-emptyはterminal reject |
| downgrade | automatic retry/downgrade forbidden |
| exporter timing | message_4 verify成功前は0回 |
| concurrent attempt | peerごとexact 1 |

RFC 9529 section 3 traceはmethod 3/suite 2のalgorithm referenceに使うが、最初にsuite 6を
提案して`[6,2]` retryするため、本profileのnegotiation-positive vectorではない。

PA-S0 vectorはsuite 2とsuite 3について、それぞれ独立したfresh
`exchange_generation`で`message_1..message_4`の4 NAC1 recordsをmaterializeする。
各recordはstage/kind/sequence/payload digest/CRCを持ち、EAD item countは0である。
Message 4 verify前のexporter callは0、成功後はclosed 8-label setの8 callsである。
`EAD_1_NONEMPTY`〜`EAD_4_NONEMPTY`は各stageでterminal reject、exporter/retry/
reject後wireは0。suite downgrade failureは同一policy revisionで自動retryせず、
fresh policy revisionとfresh session generationを要求する。

これらは
`SYNTHETIC_PROFILE_STATE_MACHINE_NOT_CRYPTO_KAT`であり、RFC 9529 traceは
`ALGORITHM_REFERENCE_ONLY_NOT_PROFILE_NEGOTIATION_POSITIVE`である。real provider KAT、
AEAD ciphertext correctness、相互運用性はPA-S2のOPEN evidenceに残す。

## 4. Carrier binding

carrier classは`1 USB_STREAM`、`2 WIFI_STREAM`、`3 COMPACT_RADIO`のclosed set。
SHA-256 inputはすべて表示順の連結である。

```text
USB =
  "NINLIL-NAC1-USB-BINDING-V1" ||
  carrier_instance_id16 || peer_id16 || connection_generation_u64be ||
  accepted_carrier_config_digest32

Wi-Fi =
  "NINLIL-NAC1-WIFI-BINDING-V1" ||
  carrier_instance_id16 || peer_session_id16 || peer_id16 ||
  network_instance_id16 || connection_generation_u64be ||
  path_generation_u32be || accepted_carrier_config_digest32

compact radio =
  "NINLIL-NAC1-RADIO-BINDING-V1" ||
  carrier_instance_id16 || channel_plan_digest32 ||
  radio_epoch_u64be || accepted_carrier_config_digest32
```

各digestはNAC1 headerとEDHOC/Attachment transcriptへ固定する。carrier migrationは同じ
sessionのbinding差替えではなくfresh Attachmentである。

### 4.1 carrier_transcript_digest（byte-exact Normative）

`carrier_transcript_digest` は **32-byte SHA-256** であり、名前や例示文字列
（例: `"carrier-transcript"` のhash）ではない。両roleが同一値を計算する
（**local role / direction は preimage に入れない**）。方向は NAC1 `kind` が
暗黙に固定する（m1 I→R, m2 R→I, m3 I→R, m4 R→I）。

```text
label = ASCII "NINLIL-PA-CARRIER-TRANSCRIPT-V1"   # exact 31 octets
schema_version_u8 = 1

preimage =
  label ||
  schema_version_u8 ||
  carrier_class_u8 ||                 # 1 USB / 2 WIFI / 3 COMPACT_RADIO
  session_id_16 ||
  exchange_generation_u64be ||        # NAC1 header exchange generation
  attempt_index_u32be ||              # 0-based EDHOC retry/attempt id
  attachment_epoch_u64be ||           # install-bound attachment generation
  method_u8 ||                        # 3
  suite_u8 ||                         # 2 or 3 (pinned for this attempt)
  cookie_mode_u8 ||                   # 0 ABSENT / 1 INCLUDED
  entry_count_u8 ||                   # 4 (no cookie) or 6 (cookie path)
  for each entry in Normative order:
    kind_u8 ||
    record_sequence_u32be ||
    nac1_total_len_u16be ||
    nac1_complete_wire_bytes          # magic..header..CRC..payload

carrier_transcript_digest = SHA-256(preimage)
```

**Entry order（cookie_mode=1 COMPACT_RADIO DoS path）:**

1. kind=1 COOKIE_CHALLENGE, sequence=0  
2. kind=2 COOKIE_RESPONSE, sequence=0  
3. kind=4 EDHOC_MESSAGE_1, sequence=1  
4. kind=5 EDHOC_MESSAGE_2, sequence=2  
5. kind=6 EDHOC_MESSAGE_3, sequence=3  
6. kind=7 EDHOC_MESSAGE_4, sequence=4  

**Entry order（cookie_mode=0 USB/Wi-Fi admitted without cookie）:**  
EDHOC_MESSAGE_1..4 only（sequence 1..4）。

**NAC1 wire scope:** each `nac1_complete_wire_bytes` is the **exact complete NAC1
record** as encoded on the carrier (88-byte header with valid CRC32C + payload).
EDHOC message octets are the **NAC1 payload** as carried (the EDHOC message wire
bytes themselves). Implementations MUST NOT re-CBOR, re-order CBOR maps, or
substitute RFC suite-6 negotiation traces for a suite-2/3 pinned attempt.

**Included:** cookie challenge/response NAC1s iff `cookie_mode=1`.  
**Excluded:** ATTACH_PROPOSE/INSTALL/CONFIRM, NAS1/NAR1 framing wrappers,
retransmit duplicates of the same kind, local_role, exporter secrets.

**Binding:** digest is written into NAI1 bytes[352:384] and NAX1 bytes[100:132].
1-byte payload flip (with CRC repair), entry reorder, exchange_generation±,
attempt_index±, attachment_epoch±, suite flip, cookie_mode flip MUST change the
digest or reject the preimage. Ambiguous “transcript” without this formula is
forbidden.

## 5. NAC1 canonical record

全整数はbig-endian。CRC32Cはreflected Castagnoli polynomial `0x82F63B78`、
initial/final XOR `0xFFFFFFFF`で、CRC fieldをzeroにしたrecord全体をcoverageとする。

| off | end | bytes | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic `NAC1` |
| 4 | 6 | 2 | version = 1 |
| 6 | 8 | 2 | header bytes = 88 |
| 8 | 12 | 4 | total bytes = 88 + payload bytes |
| 12 | 16 | 4 | payload bytes 0..512 |
| 16 | 17 | 1 | kind 1..11 |
| 17 | 18 | 1 | flags = 0 |
| 18 | 19 | 1 | carrier class 1..3 |
| 19 | 20 | 1 | reserved = 0 |
| 20 | 36 | 16 | non-zero session id |
| 36 | 44 | 8 | non-zero exchange generation |
| 44 | 48 | 4 | record sequence |
| 48 | 52 | 4 | reserved = 0 |
| 52 | 84 | 32 | non-zero carrier binding digest |
| 84 | 88 | 4 | CRC32C |
| 88 | total | 0..512 | payload |

Kind:

| value | kind | sequence |
| ---: | --- | ---: |
| 1 | COOKIE_CHALLENGE | 0 |
| 2 | COOKIE_RESPONSE | 0 |
| 3 | EDHOC_ERROR | 1..8 |
| 4 | EDHOC_MESSAGE_1 | 1 |
| 5 | EDHOC_MESSAGE_2 | 2 |
| 6 | EDHOC_MESSAGE_3 | 3 |
| 7 | EDHOC_MESSAGE_4 | 4 |
| 8 | ATTACH_PROPOSE | 5 |
| 9 | ATTACH_INSTALL | 6 |
| 10 | ATTACH_CONFIRM_DEVICE | 7 |
| 11 | ATTACH_CONFIRM_AUTHORITY | 8 |

version 1のunknown kind、wrong sequence、reserved、length、CRC、carrier/session/binding mismatchは
`CORRUPT`。framingが自己整合するfuture versionだけ`UNSUPPORTED`。magic再走査で同じ
sessionを継続しない。

## 6. NAS1 stream wrapper

USB/Wi-Fiは1つのNAC1を次の12-byte headerの後に置く。

| off | bytes | field |
| ---: | ---: | --- |
| 0 | 4 | magic `NAS1` |
| 4 | 1 | version = 1 |
| 5 | 1 | carrier class = 1 or 2 |
| 6 | 2 | header bytes = 12 |
| 8 | 4 | NAC1 record bytes 88..600 |

最大recordは612 bytes。partial readはfixed buffer内で継続する。wrapperとinner NAC1の
carrier class不一致、trailing bytes、short EOF、future versionはdelivery 0でconnectionを閉じる。
NAS1はNFL1/NWB1ではなく、Attached後のApplication pathにも使わない。

incremental ownerはone-record-per-wrapper、caller-owned 612-byte fixed bufferで、
single readと`1/6/5/79/rest`のpartial readsを同じ1 deliveryへ収束させる。short EOF、
1-byte trailing、future version、inner carrierだけを変更してinner CRCを修復したrecordは
それぞれconnection closeかつdelivery 0である。完成前にinner recordをpublishしない。

## 7. NAR1 compact-radio fragments

NAR1はpre-attachment direct one-hop packetで、relayしない。packet最大192 bytes、
header 68 bytes、payload最大124 bytes、1 record最大5 fragmentsである。

| off | end | bytes | field |
| ---: | ---: | ---: | --- |
| 0 | 4 | 4 | magic `NAR1` |
| 4 | 5 | 1 | profile = `0x12` |
| 5 | 6 | 1 | version = 1 |
| 6 | 8 | 2 | header bytes = 68 |
| 8 | 10 | 2 | total packet bytes |
| 10 | 12 | 2 | fragment payload bytes |
| 12 | 28 | 16 | session id |
| 28 | 36 | 8 | exchange generation |
| 36 | 40 | 4 | record sequence |
| 40 | 42 | 2 | complete NAC1 bytes |
| 42 | 43 | 1 | fragment index 0..count-1 |
| 43 | 44 | 1 | fragment count 1..5 |
| 44 | 60 | 16 | SHA-256(complete NAC1)[0..16) |
| 60 | 64 | 4 | fragment offset |
| 64 | 68 | 4 | CRC32C |

offsetは`index * 124`、non-final payloadは124 exact、finalは残長exact。pre-auth owner keyは
`(source_locator_digest32, session_id16, exchange_generation_u64,
record_sequence_u32, complete_nac1_bytes_u16, digest16, fragment_count_u8)`であり、
source locatorはcookie認証前の先頭identityである。このkeyごとにexact 1 reassembly ownerとし、
duplicate same bytesは無進捗、conflicting duplicate、gap、overlap、mixed tuple、digest/inner
NAC1 mismatchは全体を破棄する。fragmentを受けてもEDHOC identity成功とはみなさない。

固定5-slot executable ownerはcanonical orderと逆順を同じcomplete NAC1へ収束させる。
exact duplicateはduplicate countだけを増やし、unique progressは増やさない。
conflicting duplicate、1-fragment loss後のidle timeout、offset overlap、mixed tuple、
outer/inner generation mismatch、source locator mismatchはterminal discardかつ
published bytes 0である。

## 8. Stateless cookie

compact radioのunknown peerは必須。cookie secretはcontroller RAMにcurrent/previous各32 bytes、
**exact 2-second** bucketを使う（gateがvectorと独立に`time_bucket_seconds=2`をpinし、
2→3のcoherent driftを拒否する）。

```text
cookie = HMAC-SHA-256(
  cookie_secret32,
  "NINLIL-NAC1-COOKIE-V1" ||
  carrier_class_u8 ||
  carrier_binding_digest32 ||
  source_locator_digest32 ||
  session_id16 ||
  exchange_generation_u64be ||
  SHA-256(original_message_1) ||
  time_bucket_u64be)
```

challenge payloadはcookie32、response payloadは
`cookie32 || original_message_1_length_u16be || original_message_1`。
responderはcurrent/previous bucket × current/previous secretをconstant-time比較する。
NAC1 headerを含むresponseはexact 159 bytes
（header 88 + cookie 32 + original_message_1_length_u16be 2 + original_message_1 37）で
NAR1の124-byte fragment payloadを超えるため、
成功前に許すstateはexact 1件のfixed 2-fragment cookie scratchだけである。EDHOC、
credential resolver、NAP1/NAI1、general reassemblyをallocationしない。scratchは
source-locator-first owner key、per-source exact 1、global exact 8、token bucket capacity 2、
2-second refill、exact 9-second idle期限、conflicting duplicate即破棄を持つ。cookieは
current/previousの2 bucketsだけを受け入れ、それより古いbucketをterminal discardする。
同一sourceの2件目、global 9件目をallocationせず拒否し、idle expiry後だけ再admitする。
cookie検証成功前のidentity allocationとcredential resolver callはともに0である。
challenge bytesは受信record bytes以下に保つ。cookie成功はauthenticationではない。

machine authorityはfixed two-fragment scratchを`EMPTY`、fragment 0 only、fragment 1 only
として実際に遷移させる。同一index・同一payloadのduplicateはno-progress、同一indexで
1 byteでも異なるpayloadはscratchをzero/releaseしてterminal、fragment 0/1が揃った時だけ
complete NAC1を引き渡してreleaseする。older cookie bucketはfresh requestだけでなく、
既にfragment 0を所有するscratchにも適用し、terminal releaseする。

境界はinclusive/exclusiveを次のとおり固定する。

- token refill前の`1999 ms`はdenyのまま、exact `2000 ms`で1 tokenをrefillしてadmitする。
- idle `8999 ms`ではscratchを保持し、exact `9000 ms`でexpire/releaseする。
- current bucketとprevious bucketはallocationを許し、それ以前は許さない。
- per-source 1、global 8、token capacity 2はallocation前に実状態から判定する。

vectorは31 input transitionsと17 named branchesを持ち、各branchを1回以上実行する。
Python、Node.js、C11は記録済みoutcomeを読むだけでなく、各自のbounded ownerへ同じinputを
投入し、result、branch、active/source count、token、received mask、expiry、
completion/release/terminal countersを行ごとに再計算する。

## 9. Protected exchange

message_4成功後、sequence 5..8をAES-CCM-16-64-128で保護する。direction別key/IV:

| label | purpose | bytes |
| ---: | --- | ---: |
| 32768 | initiator→responder control key | 16 |
| 32769 | responder→initiator control key | 16 |
| 32770 | initiator→responder base IV | 13 |
| 32771 | responder→initiator base IV | 13 |
| 32772 | Hop IR traffic secret | 32 |
| 32773 | Hop RI traffic secret | 32 |
| 32774 | E2E IR traffic secret | 32 |
| 32775 | E2E RI traffic secret | 32 |

```text
control_exporter_context =
  SHA-256("NINLIL-ATTACH-PROTECT-CONTEXT-V1" || NAX1)
traffic_exporter_context =
  SHA-256("NINLIL-ATTACH-TRAFFIC-CONTEXT-V1" ||
          NAX1 || install_digest32)
nonce13 = base_iv13 XOR
          (0x00 || exchange_generation_u64be || record_sequence_u32be)
AAD = complete NAC1 header bytes[0..84) with CRC field excluded
```

plaintextに8-byte tagを付加する。Open成功前はplaintext publication 0。sequence、kind、
direction、NAX1、carrier transcript、install digestのどれか1 bit差で失敗する。

NAX1はexact 160 bytesで、method/suite/session/generation、双方credential digest、
carrier transcript digest、authority id/termを固定する。raw C struct/paddingは使わない。

## 10. Proposal, install and confirmation

### 10.1 NAP1 proposal

NAP1はexact 208 bytes。deviceが割り当てるRI inbound Hop/E2E context idとminimum key
generation、identity/site/authority/membership/credential/revocation/assignment、
E2E security id/epoch、membership grant digestを含む。context idは
`1..UINT32_MAX-1`、generationはnon-zeroでdurable high-waterより大きい。

### 10.2 NAI1 install

NAI1はexact 416 bytes。attachment id、双方stable identity digest、site/authority、
membership/attachment/lease、trusted lease clock window、credential/revocation/assignment、
4 directional context id、4 key generation、E2E security id/epoch、route policy、
membership grant、carrier transcript、`SHA-256(NAP1)`を含む。

authorityが割り当てるIR inbound IDsとdevice proposalのRI IDsを混同しない。

```text
install_digest =
  SHA-256("NINLIL-PRODUCTION-ATTACH-INSTALL-V1" || NAP1 || NAI1)
```

### 10.3 NAT1 confirmation

NAT1はexact 96 bytesでinstall digest、attachment id、membership/attachment/E2E/lease
epoch、assignment epochを固定する。device confirmationとauthority confirmationは同じ
NAT1を逆方向keyで保護する。両方揃う前にactive handleをpublishしない。

## 11. Atomic durable install

local nodeのpost-imageはexact:

| layer/direction | lane | N6AL | N6HW | total |
| --- | ---: | ---: | ---: | ---: |
| Hop IR | 2 | 1 | 1 | 4 |
| Hop RI | 2 | 1 | 1 | 4 |
| E2E IR | 1 | 1 | 1 | 3 |
| E2E RI | 1 | 1 | 1 | 3 |
| PENDING Attachment marker | — | — | — | 1 |
| **single FULL** |  |  |  | **15** |

全key/valueは[30章](30-r6-secure-radio-wire.md)の**canonical N6 codec wire**でmaterializeし、
**complete keyのunsigned-byte lexicographic順**へsortする。synthetic seed filler
（例: `NINLIL-PA-N6-VALUE-V1`）はruntime storage/KATに使わない。laneはN6TX/N6RX 68B、
N6AL 56B、N6HW 28B、N6AT 120Bのexact layout+CRCを持つ。

NAB1 vectorは15-member semantic manifestでありwire/storage formatではない。各20-byte
NAB1 entryは
`member_kind_u8 || direction_u8 || lane_u8 || local_side_u8 ||
context_id_u32be || key_generation_u64be || key_bytes_u16be || value_bytes_u16be`で、
対応するcomplete key（lane 48B / N6AL 24B / N6HW 32B / N6AT 20B）をoracleが独立に
再構成して順序とidentityを検証する。semantic表示順（hop_ir first 等）は受理しない。
`local_side=1 INBOUND_RX / 2 OUTBOUND_TX`で、initiator localはIR=OUTBOUND/RI=INBOUND、
responder localは逆、markerだけ0である。device roleとauthority roleはそれぞれ
exact 15-key inventoryとrole-specific N6AT key/valueを持つ。

### 11.1 Chosen durability model: Write-Set Observed-OLD / Proposed-NEW

**PA-S0は attachment-scoped namespace を採用しない**（bounded GC/selectionを未定義のまま
導入しない）。代わりに **write-set value-image model** をnormativeとする:

1. Attachment FULL write-set = exact 15 complete keys（unsigned-byte order）。
2. 各keyに `old_present`、**observed OLD value/context digest**（absent可）、
   **proposed NEW value/context digest**（canonical N6 wire）を持つ。OLD cardinalityは
   この15個のper-row flagsから導出し、protocol constantにしてはならない。
3. N6AL/N6HW complete keyは`attachment_id`を含まない。同一membership/peerでの再Attachmentでは
   allocator floor / active count / high-water が既にdurableに存在する。**OLD=0 member強制は
  禁止**。再attachのvalid observed OLD（非空AL/HW/lane）をpartial/corruptと分類してはならない。
4. Markerだけがattachment-scopedであり、OLDではabsent、NEWでPENDINGを提案する。
5. N6AL `next_free_or_peer_floor` と N6HW `high_water_key_generation` は **単調非減少**
   （10,000 cyclesすべてで1 cycleごとにrestartしてもfloor/high-waterを下げない）。
6. `COMMIT_UNKNOWN`はwrite-set上の **per-row value-image** を分類する
   （**key-count aloneは禁止**。`present_count==0 → EXACT_OLD` は再attachでは偽）:
   - 各write-set keyについて durable value(+context digest) が observed OLD と一致 /
     proposed NEW と一致 / どちらでもない(THIRD) / STABLE(OLD==NEW) を判定する。
   - **EXACT_OLD**: pure-NEW が0（全keyがOLD、STABLEまたは正当にOLD-absent）。
     OLD countは固定値ではない。PA-S0のadversarial fixtureは合法なlane OLDを確実に
     通すためnon-marker 14 rowsをpresent、markerだけabsentにする。
   - **EXACT_NEW**: pure-OLD が0 かつ marker present で PENDING/ACTIVE。
   - **PARTIAL_n** (1..14): pure-NEW がちょうど n、残りは OLD/STABLE。
   - **EXTRA / FOREIGN**: write-set外key
   - **THIRD/MISMATCH**: いずれかのkeyがOLDでもNEWでもない
7. activationはmarkerだけPENDING→ACTIVE single-key FULL。activation CUは
   marker OLD=PENDING / NEW=ACTIVE だけを受理。

Attachment markerはkey 20 bytes、N6AT value 120 bytes。state closed setは
`1 PENDING`、`2 ACTIVE`、`3 FENCED`。valueはattachment id、membership/attachment/lease/E2E
epoch、authority term、credential revision、revocation generation、assignment epoch、
install digest、CRC32Cを持つ。reserved bytes 10..11はexact 0。key roleとvalue role
不一致、unknown state、CRC/length/reserved違反はcorrupt/fenced。
15-key FULLはPENDING marker込みのexact NEW。NEW post-imageは**全15 memberの
complete key + value + context digest**を固定し、non-marker rowのvalue/context
digest置換はcorrupt/fencedである（key inventory一致だけでは受理しない）。

現行N6の4-key/3-key APIを逐次呼出すこと、先行handle publication、partial rollbackの推測を
禁止する。future private batch ownerは最大32 mutations内の15-key FULLをsole pathにする。

`COMMIT_UNKNOWN`後はmutable ownerを閉じ、fresh read-only scanでexact OLDまたはexact NEWだけを
受理する。PARTIAL/EXTRA/THIRDはcorrupt/fenced。

15-key FULLのmarkerはPENDINGである。authorityがdevice confirmationをverifyした後、authorityは
自local markerをPENDING→ACTIVEへsingle-key FULLしfresh read-only verifyしてからauthority
confirmationを送る。deviceはauthority confirmationをverifyした後、同じsingle-key FULLと
再読取を行う。ACTIVE verify完了前のhandle/Application TX/RXは0である。

## 12. State and failure

```text
IDLE -> COOKIE (radio only) -> EDHOC_1 -> EDHOC_2 -> EDHOC_3 -> EDHOC_4
     -> PROPOSE -> INSTALL_VERIFIED -> LOCAL_FULL_PENDING
     -> LOCAL_FULL_OK -> DEVICE_CONFIRMED -> AUTHORITY_CONFIRMED -> ATTACHED
```

同一peerで2 attempt、same session/generation再利用、sequence skip/replay、timer expiry、
carrier epoch change、credential/authority/revocation/assignment/lease changeは候補をterminalにする。
definite durable failureは候補secretをzeroizeしfresh attemptだけ許す。commit unknownは
recovery完了までpeer/siteをfenceする。

restart時、durable ACTIVE markerだけでsecret/handleを復元しない。old rowはDORMANT/FENCED、
Application TX/RX 0。fresh EDHOC/fresh contextsで新Attachmentを作り、別のAccepted GC contractが
old namespaceを削除する。

## 13. Resource, ownership and timing

v1 integration ceiling:

| resource | endpoint | controller |
| --- | ---: | ---: |
| active exchanges | 1 | 8 |
| active exchange per peer | 1 | 1 |
| pending admissions | 4 | 32 |
| radio reassemblies | 1 | 8 |
| complete NAC1 buffer | 600 B | 8 × 600 B |
| stream wrapper buffer | 612 B | 8 × 612 B |
| fragments per record | 5 | 5 |
| retransmissions per record | 3 | 3 |
| stream exchange deadline | 15 s | 15 s |
| radio exchange deadline | 60 s | 60 s |
| radio fragment idle timeout | 10 s | 10 s |

ownerはsingle serialized task/loopで進め、callbackはbounded eventをcopyするだけで再入しない。
caller-owned workspace、fixed records、checked arithmeticを使い、heap/VLAを禁止する。
credential resolver、clock、carrier、crypto、storage callbackから返るborrowはcall中だけ有効。

candidate EDHOC libraryを採用する場合はcustom allocatorだけを使い、default VLA/heap backendを
禁止する。正式ceilingは全allocation traceをmaterializeしてからAcceptedにする。現時点の
feasibility buildからproduction stack/heap適合を主張しない。

terminal、cancel、timeout、authentication failure、definite storage failureでは
ephemeral private key、PRK、exporter output、traffic secret、AEAD key/IV、decrypted
proposal/install、credential copyをzeroizeする。durable FULLに渡した秘密のownershipはbatch
ownerへ移り、FULL result前にcallerへ戻さない。

## 14. Machine-readable acceptance candidate

正本vector候補:
`spec/vectors/production-attachment-edhoc-v1.json`。

独立gateは最低限:

- Python generator freshness/self-test
- Python independent semantic/byte gate + mutation self-test
- Node.js independent semantic/byte gate + mutation self-test
- generated fixtureを読むstrict C11 validator/reassembly test
- NAC1/NAS1/NAR1/NAP1/NAI1/NAX1/NAT1/N6AT/NAB1のlength/reserved/CRC
- suite2/3、message4必須、EAD absent、exporter label/context exact
- cookie current/previous bucket/secret、source/carrier/session mutation
- actual fixed-slot NAR ownerによるreorder success、duplicate no-progress、
  conflict/gap/overlap/mixed/source/inner mismatchのzero-publication
- actual 612-byte NAS incremental lifecycle（partial/short/trailing/future/inner mismatch）
- exact prerequisite claims/local static-DH port/failure matrix
- suite2/3それぞれのMessage 1..4、EAD_1..4 terminal、no-auto-downgrade
- source-first cookie scratchの31実遷移・17分岐、fragment lifecycle、
  per-source/global/token quota、1999/2000 ms refill、8999/9000 ms idle、
  current/previous/older bucket
- closed repository machine-source protocol magic registry（duplicate JSON、
  undeclared/stale/missing/collision/bad type/domain mutation）
- 15-member exact atomic set、role/state/digest/key-generation mutation
- per-row OLD/NEW/STABLE/THIRD、合法lane OLD、10,000 restart monotonicity
- RFC 9529 reference digest（profile negotiation positiveとは別）

stable acceptance IDsは
`PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD`から
`PA-INDEPENDENT-COHERENT-DRIFT-REJECT`まで、baseline review
[`2026-07-31-production-attachment-independent-review.md`](reviews/2026-07-31-production-attachment-independent-review.md)
に列挙した16件をPython/Node/C11で実行する。

vectorのopaque ciphertextはAEAD実装完成を主張しない。dependency採用後、Host/ESP
cross-provider KATでreal ciphertextへ置換し、同じreview unitでstatusを更新する。

## 15. OPEN evidence and acceptance order

| tranche | required result | current |
| --- | --- | --- |
| PA-S0 | Proposed docs + canonical vectors + 3-language gates | repair candidate complete; fresh independent re-review pending |
| PA-S1 | dependency/source/license/allocator acceptance | OPEN |
| PA-S2 | suite2/3 Host+ESP crypto、peer credential resolver、local static-DH key operator | OPEN |
| PA-S3 | NAS1/NAR1 owner + EDHOC state owner | OPEN |
| PA-S4 | protected exchange + sole 15-key N6 batch owner | OPEN |
| PA-S5 | restart/rotation/revocation/join-storm/fault matrices | OPEN |
| PA-S6 | USB/Wi-Fi/SX1262 HIL and independent final review | OPEN |

PA-S0だけで本章またはADRをAcceptedにしない。PA-S1〜S6が揃うまではpublic ABI、
RELEASE_SUPPORTED、production、field/legalをすべて非主張とする。
