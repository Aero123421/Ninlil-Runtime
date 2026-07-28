# ADR-0022: Domain Store schema 1 Runtime binding and LAB separation

状態: **Proposed — docs-only（implementation / acceptance pending）**
提案日: 2026-07-28
受入日: —（未受入）
非主張: D3 complete、D4 writer、Stage 5 complete、public `runtime_create()` publish、
automatic migration、public ABI change、ESP-IDF/HIL/production support

## Context

[17章](../17-foundation-domain-store.md)のDomain Store schema 1は、family 1–4
metadata、family 5/6 domain row、witness、identity、clock、healthを同じ recovery
contractへ結ぶ。公開 Runtime はfull read-only recovery、unresolved old/new group 0、
identity、trusted clock、healthを完了するまでhandleをpublishできない。

現在のV1 LAB private Runtimeは同じStorage ABIとfamily 1–4 keyを使う一方、
`NRS`、`TX`/`CN`/`DS`/`EV`/`OC`/`ES`/`RT`/`AP`、`RV`、`ER`/`ED`、
`BS`、`M4T`、`C3R`という別のdurable profileを持つ。加えて旧LAB Stage 5はformat 1
bootstrapに対し、15 BASELINE `WITNESS_HEAD_INDEX` + 1 `CLOCK_BASELINE`をone FULLで作る。
この16-row metadata groupはread-only quarantineでだけLAB-compatibleと認識するが、
LABの`NTS3` transaction snapshotや`NEL1` event ledgerは、Domain Storeのcanonical raw
identity、primary value digest、witness member old/newを復元する根拠にならない。

Storage ABIには「このnamespaceが過去に存在したことがない」と証明する操作はない。
したがって履歴を推測せず、initial adoptionでは同じREAD_WRITE transactionの
pre-mutation snapshotで観測したrowと、existing/retry classificationではfresh
READ_ONLY snapshotで観測したrow、ならびに永続binding discriminatorだけをauthorityとする
必要がある。

### Scope、owner、failure domain、依存方向

本ADRのdecision ownerは、1回のprivate Runtime create候補にexactly 1つ存在する
**Canonical startup owner**である。このownerはcreate入力とPlatform Port tableを
候補内へcopy-ownし、同じ候補のStorage transaction/iterator、T0–T7 progress、
Bearer open、public handle publishを直列化する唯一のmutation/publication authorityである。
LAB quarantine/export classifierは別のread-only workerとして実行できるが、
Canonical startup ownerへsuccess bit、binding、row、callback、handleを返してpublicationを
進めてはならない。2つのstartup owner、borrowed create config、workerからの直接publishは
禁止する。

Failure domainは、createで選ばれた**1つのexact Storage namespace**と、それへまだpublish
されていないRuntime候補全体である。Framing corruption、cross-row conflict、
`COMMIT_UNKNOWN`、trusted clock/health/T7失敗のいずれも候補全体をfenceし、
Bearer/callback/public handleの部分成功へ縮小しない。別namespace、既存のpublished
Runtime、read-only export artifactまで連鎖停止させない。

依存方向は次の一方向だけである。

```text
public runtime_create request
 -> Canonical startup owner
 -> T0 -> T1a -> T1b
 -> D3 recovery validation (T2)
 -> D4 mutation/re-scan (T3)
 -> identity recovery (T4)
 -> trusted-clock sample/FULL/re-scan (T5)
 -> durable health reconstruction (T6)
 -> Bearer open -> metrics entropy
 -> T7 publication gate -> public handle
```

後段から前段のtruthを生成する、Bearer/clock/LAB classifierをStorage recoveryのauthorityに
する、またはpublic handleからstartup候補を逆構築する依存は禁止する。

[12章](../12-foundation-abi.md)と[17章](../17-foundation-domain-store.md)のNormative
contract、および既存Accepted ADRが本Proposed ADRより常に優先する。競合を発見した場合は
既存contractを変更せず、本ADRをProposedのままfail closedで修正する。本ADRのvectorや
private実装結果だけでAccepted contractのstatus、wire、Storage ABI、public ABIを
上書きしない。

## Decision

### 0. Decision register

| ID | 決定 | 理由 |
| --- | --- | --- |
| D22-01 | Domain bindingをformat 2としてformat 1 LABから分離 | downgrade、silent LAB adoption、profile混同を永続的にfenceする |
| D22-02 | initial adoptionは同じREAD_WRITE snapshotの0-rowだけ | Storage ABIがnever-existedを証明しないため |
| D22-03 | T1a bootstrap、T1b metadata、T5 clockを別FULL groupにする | 各`COMMIT_UNKNOWN`をOLD/NEWの二値へ閉じる |
| D22-04 | Canonical classifierとLAB quarantine/export classifierを分離 | LAB evidenceをpublic Domain successへ昇格させない |
| D22-05 | migrationはread-only export + 別namespace explicit re-bootstrapだけ | LAB rowから失われたquota/callback/effect truthを推測しない |
| D22-06 | T2、T3、T4、T5、T6、T7を別のfail-closed stage/KATにする | aggregate success bitによる段階skipを防ぐ |
| D22-07 | malformed current framingとframing-valid future versionを別statusにする | corruptionは`STORAGE_CORRUPT`、互換性不足は`UNSUPPORTED`として[12章]へ一致させる |
| D22-08 | first kind-1 SERVICE_REGISTERをM=5の単一FULL groupとexplicit reattachに限定 | callbackを永続化せず、COMMIT_UNKNOWN後のdurable truthとvolatile handleを混同しない |

### 1. 0-row snapshotだけをinitial adoption authorityにする

Canonical Domain profileのinitial adoption候補は、fresh `READ_WRITE` transactionを
beginし、mutation前にnamespace全体を先頭からiterateし、最初の`iter_next`が
`NOT_FOUND`となった**authoritative 0-row pre-mutation snapshot**だけである。同じ
transactionでiteratorをcloseした後にだけT1aの17 CREATEをstageし、1回のFULL commitへ
進む。別`READ_ONLY` transactionで0-rowを観測してから`READ_WRITE`へupgradeする操作は
Storage ABIに存在せず、別transactionで再beginしてその観測を採用根拠にすることも禁止する。
Storage ABIが証明できない「never existed」「消去歴なし」は要件にも成功理由にも使わない。

0-row以外は既存namespaceである。既存rowを削除してemptyとみなす、unknown rowを無視する、
LAB rowを上書きする、best-effort resetする、またはscanとbootstrapを別snapshotで競合させる
ことは禁止する。Provider外でnamespaceを消去した場合はこのcontract外のoperator data-lossで
あり、Runtimeは消去前の履歴を再発見できるとは主張しない。

#### 1.1 Domain-only private binding discriminator

Canonical Domain profileはpublic C ABIを変えず、private Type 1 bindingを
**binding format 2**へ進める。Format 1はV1 LAB、format 2はDomain-onlyであり、
相互にfallbackしない。

Format 2 payloadはformat 1の167 bytesへ次の32 bytesをprofile name直後に追加した
exact 199 bytes、`NLR1` value total 215 bytesである。

```text
binding_format             u32 = 2
resource_profile_name      RAW16 length 25,
                           ASCII "NINLIL-FOUNDATION-SMALL-1"
storage_profile_id         16 bytes =
                           4e494e4c494c2d444f4d41494e2d5331
                           # ASCII "NINLIL-DOMAIN-S1"
storage_profile_revision   u32 = 1
minimum_writer_generation  u32 = 2
rollback_epoch             u64 = 1
storage_schema             u32 = 1
role, environment, runtime_id, limits, retention
                           format 1の残り136 bytesと同じ順序・幅
```

Canonical writer generationはexact 2である。Open時はformat、profile ID、revision、
`writer_generation >= minimum_writer_generation`、rollback epoch、schema、および残りbinding
全fieldを先にexact検査する。Format 1、unknown profile ID、revision/epoch rollback、
writer generation不足は`NINLIL_E_UNSUPPORTED`で、write、handle、callback、Bearer openは0。

このformat差がdurable downgrade fenceである。最後にsupportしたLAB binaryをformat 2
fixtureへ向けた互換試験は、binding decodeでpublish前に拒否し、Storage call transcript上の
READ_WRITE begin/put/erase/commitをexact 0としなければならない。Canonical buildは
`ninlil_v1_durable_recovery_publication_gate*`をpublication authorityとしてlink/callせず、
LAB classifierをread-only quarantine/export用途にだけ隔離する。

Format 2 bindingを含むnamespaceは再bootstrapしない。完全なexisting Domain snapshotへの
reattachだけを許し、format 2 bindingのerase、format 1へのdowngrade、rollback epoch低下、
in-place LAB conversionはpublic Runtime pathに存在させない。

Machine KATはexact positiveに加え、unknown format、unknown profile ID、revision rollback、
minimum writer generation不足、rollback epoch regression、schema mismatch、最後にsupportした
LAB binaryからformat 2を開くdowngradeをCRC-validなsingle-cause bytesで固定する。全negativeは
`NINLIL_E_UNSUPPORTED`、READ_WRITE begin/put/erase/commit、Bearer、callback、handle、
publish exact 0である。

### 2. Bootstrap、metadata、clockを別のauthoritative groupにする

Initial state machineは次のclosed sequenceである。

| Node | Authoritative pre-state | One FULL mutation | Authoritative post-state |
| --- | --- | --- | --- |
| T0 | fresh READ_WRITE transactionのmutation前namespace全体0 row | mutation 0 | 同transaction内bootstrap候補 |
| T1a | T0と同じREAD_WRITE transaction/pre-mutation snapshot | family 1–4 exact 17 CREATE、format 2 bindingを含む | 17/17 present |
| T1b | fresh scanで17/17 exact | 15 BASELINE `WITNESS_HEAD_INDEX` + 1 UNINITIALIZED `CLOCK_BASELINE` CREATE | 17 + 16 metadata |
| T2–T4 | fresh full scan | D3-S4..S12、D4、identity recovery | cross-row truth確定 |
| T5 | exact UNINITIALIZED clock | Bearer open前に取得してrequestへ固定したtrusted sampleでCLOCK_BASELINE単一REPLACE | exact TRUSTED clock |
| T6 | fresh full scan | mutation 0 | durable health再構成 |
| T7 | T0–T6、Bearer open、metrics entropyとpublish gate全部green | mutation 0 | public handle publish可 |

T1aの17 recordsはbinding 1、identity 1、counter 4、capacity 11で、key unsigned-byte
lexicographic順にstageする。Format 2によりencoded key+valueはexact **1,343 bytes**、
portable logical usageはexact **1,615 bytes**である。

T1bの16 recordsは、unsigned-byte lexicographic順ではsingleton `CLOCK_BASELINE`
（subtype `62`）が先、その後に15個の`WITNESS_HEAD_INDEX`（subtype `7d`、composite
digest順）が続く。CLOCK bodyはstate=UNINITIALIZED、reserved=0、epoch/now/generation全zero。
各indexはBASELINEで、対象family 3/4 keyとそのbootstrap value digestをexact保存し、
head digestはzeroである。T1bはTRUSTED clockを作らない。

各commitの`COMMIT_UNKNOWN` truthは次だけである。

| Group | OLD | NEW | その他 |
| --- | --- | --- | --- |
| T1a 17 bootstrap | namespace全体0 row | exact 17/17 format 2 rows | 1..16、extra、format mismatchはcorrupt/fenced |
| T1b 16 metadata | metadata 0/16かつ17 bootstrap exact | metadata 16/16 exact UNINITIALIZED | 1..15、extra、TRUSTED混入はcorrupt/fenced |
| T5 clock | exact UNINITIALIZED value | request時に固定したexact TRUSTED post-value | missing、第三値、epoch/sample差はcorrupt/fenced |

`COMMIT_UNKNOWN`後はmutable instanceをclose/fenceし、同じtransactionをretryしない。
次createのfresh READ_ONLY classification snapshotだけがOLD/NEWを決める。既存namespace、
retry、COMMIT_UNKNOWN収束のREAD_ONLY classificationからT1a mutationへupgradeせず、
OLDと確定したinitial retryはfresh READ_WRITE transaction内で0-rowを再証明してからだけ
T1aを再実行する。T1a NEWでもT1b、T5、T6を飛び越えない。T5とT6の両方が完了する前は
public handle、callback、send、Bearer openは0である。T6完了後にだけBearer open、
metrics entropy、T7 publishの順へ進む。

### 3. Canonical classifierとLAB quarantine classifierを分離する

Canonical recoveryはformat 2 bindingを最初に確定し、その後[17章](../17-foundation-domain-store.md)
のfamily 1–6 scannerだけをpublication authorityにする。LAB allowlistの「認識できた」を
Domain successへ変換しない。

Read-only quarantine/export classifierは、下表の34 kindをLAB row evidenceとして認識する。
Kind 1–19は一部のkey grammarがDomainと共有されるため、format 1 bindingがnamespace profile
authorityである。Kind 18/19だけは旧LABが実際に作るmetadata shapeの例外で、format 1 exact
17-row bootstrapと、同じbootstrapの4 counter + 11 capacityを指すexact 15 BASELINE
index、ならびにexact UNINITIALIZEDまたはTRUSTED `CLOCK_BASELINE`の
**complete 16-row group**が揃う場合だけ
metadata-present `EXACT_LAB`である。Metadata 0/16はpre-metadata LABとして許すが、
index 1..14、index 15 + clock 0、index 0 + clock 1、index 16以上、clock 2個以上、member
key/value digest不一致、WITNESSED index混入は`CORRUPT`であり、isolated kind 18/19 rowを
namespace successへ昇格しない。

Format 2 binding + exact canonical 16-row metadataはDomain initialization/recovery候補として
canonical scannerへ渡し、LAB successへ変換しない。Format 2 bindingとkind 20–34が同居する、
またはformat 1 bindingとmetadata exception以外のcomplete Domain semantic/witness groupが
同居する場合は`MIXED`である。同じType 1 keyを持つformat 1/2 valueのduplicate iterator rowは
下記provider corruptionでありMIXEDではない。Format 1 authorityがないLAB-distinct rowだけの
namespaceは`UNSUPPORTED`、format 2 authorityを持つLAB-distinct rowは`MIXED`である。

Isolated row positiveは、1 rowが表のpredicateに一致してrow status/kindを返すことだけを
証明し、namespace aggregate `EXACT_LAB`を単独では主張しない。Namespace-level
`EXACT_LAB` positive fixtureはformat 1のexact 17-row bootstrapを必ず同梱し、対象kindの
追加rowとcross-row predicateを全て満たす。Kind 30は同じtransaction ID、payload length、
routeを持つmatching NTS3 transaction rowを同梱し、kind 33のkey runtime IDはformat 1
bindingのruntime IDとexact一致させる。Kind 20は`slot < max_services`、kind 18/19は上記
complete metadata groupを要求する。Mutation fixtureも同じnamespace contextで対象rowだけを
変え、`CORRUPT > MIXED` precedenceを維持する。

Format 1とformat 2は同じType 1 complete keyを使うため、同一namespaceに両方を別rowとして
置くことはできない。Iteratorが同じcomplete keyを2回返すfixtureはStorage provider contract
corruptionであり、row=`NINLIL_E_STORAGE_CORRUPT`、namespace=`CORRUPT`とする。MIXED vector
には数えない。

#### 3.1 Exact row predicates

表中の略記は次を意味する。

- `RS1/RS2/RS3/RS4`: exact current root/key、`NLR1` type 1/2/3/4、
  record version 1、declared length、CRC32C、全reserved/enum/boolean invariantを検査し、
  key suffixとdecoded kindが一致する。RS1は**binding format 1**とそのfull binding exact。
- `DS(type,state)`: current family 6 key、complete typed `NLR1` validation、記載subtype/state、
  key/body/header/PVD/head invariantの全てが一致する。
- `NTS3(p)`: key length 18、prefix `p`、suffix transaction ID non-zero。Valueはmagic
  `NTS3`、schema 1.0、reserved 0、declared body/total length 20..3072、CRC32C validで、
  full canonical decodeが成功しdecoded transaction IDがkey suffixとexact一致する。
- `NEL1(k)`: key length 34、prefix `ER`または`ED`、transaction IDとoperation IDが
  ともにnon-zero。Valueは`NEL1` schema 1.0のfull decode、operation kind/state matrix、
  canonical request digest、reserved/trailing/CRCを検査し、両IDがkeyとexact一致する。

| Kind | Name | Exact key predicate | Exact value predicate |
| ---: | --- | --- | --- |
| 1 | RS_BINDING | `4e494e4c494c000101` length 9 | RS1、format 1 |
| 2 | RS_IDENTITY | `4e494e4c494c000102` length 9 | RS2 |
| 3 | RS_COUNTER_TRANSACTION | root + `0301` length 10 | RS3、kind 1 |
| 4 | RS_COUNTER_ORDERED_INPUT | root + `0302` length 10 | RS3、kind 2 |
| 5 | RS_COUNTER_ASSIGNED_OWNER | root + `0303` length 10 | RS3、kind 3 |
| 6 | RS_COUNTER_VISITED_OWNER | root + `0304` length 10 | RS3、kind 4 |
| 7 | RS_CAPACITY_SERVICE | root + `0401` length 10 | RS4、kind 1 |
| 8 | RS_CAPACITY_TRANSACTION | root + `0402` length 10 | RS4、kind 2 |
| 9 | RS_CAPACITY_TARGET | root + `0403` length 10 | RS4、kind 3 |
| 10 | RS_CAPACITY_OUTBOX_BYTES | root + `0404` length 10 | RS4、kind 4 |
| 11 | RS_CAPACITY_DELIVERY | root + `0405` length 10 | RS4、kind 5 |
| 12 | RS_CAPACITY_EVENT_SPOOL_COUNT | root + `0406` length 10 | RS4、kind 6 |
| 13 | RS_CAPACITY_EVENT_SPOOL_BYTES | root + `0407` length 10 | RS4、kind 7 |
| 14 | RS_CAPACITY_RESULT_CACHE | root + `0408` length 10 | RS4、kind 8 |
| 15 | RS_CAPACITY_EVIDENCE | root + `0409` length 10 | RS4、kind 9 |
| 16 | RS_CAPACITY_INGRESS | root + `040a` length 10 | RS4、kind 10 |
| 17 | RS_CAPACITY_DEFERRED_TOKEN | root + `040b` length 10 | RS4、kind 11 |
| 18 | DOM_WITNESS_HEAD_INDEX | family 6 subtype `7d` current exact key | DS(`7d`, BASELINE)、memberはfamily 3/4 exact key |
| 19 | DOM_CLOCK_BASELINE | family 6 subtype `62` singleton exact key | DS(`62`, UNINITIALIZEDまたはTRUSTED) |
| 20 | SPINE_SERVICE_MARKER | `4e5253 || slot:u8` length 4 | length 16、全byte `a1`; cross-rowで`slot < max_services` |
| 21 | SPINE_TXN_ADMISSION | `5458 || txid[16]` | NTS3(`TX`) |
| 22 | SPINE_CANCEL_ADMISSION | `434e || txid[16]` | NTS3(`CN`) |
| 23 | SPINE_DELIVERY_STARTED | `4453 || txid[16]` | NTS3(`DS`) |
| 24 | SPINE_DELIVERY_EVIDENCE | `4556 || txid[16]` | NTS3(`EV`) |
| 25 | SPINE_DELIVERY_OUTCOME | `4f43 || txid[16]` | NTS3(`OC`) |
| 26 | SPINE_EVENT_SPOOL | `4553 || txid[16]` | NTS3(`ES`) |
| 27 | SPINE_EVENT_RESUME | `4552 || txid[16] || opid[16]` | NEL1(RESUME) |
| 28 | SPINE_EVENT_DISCARD | `4544 || txid[16] || opid[16]` | NEL1(DISCARD) |
| 29 | SPINE_RETRY_STATE | `5254 || txid[16]` | NTS3(`RT`) |
| 30 | SPINE_RESERVATION | `5256 || txid[16]` | exact NRV1 32-byte decode、route/payload/reserved/CRC valid |
| 31 | M4_INSTALL_TOKEN | exact M4T key below | exact 72-byte M4T value below |
| 32 | C3_REPLAY_ADMISSION | exact C3R key below | exact 48-byte C3R value below |
| 33 | SPINE_BEARER_STATE | `4253 || runtime_id[16]`、non-zero、length 18 | exact NBS1 48-byte value、key runtimeとlive binding一致 |
| 34 | SPINE_ATTEMPT_PREPARE | `4150 || txid[16]` | NTS3(`AP`) |

NRV1はmagic `4e525631`、schema 1.0、payload length u32、route u8 known、
byte 13 exact 1、bytes 14..27 zero、CRC32C bytes 0..27をbytes 28..31 big-endianへ
保存する。Key transaction IDはnon-zeroで、cross-row transaction snapshotとpayload/routeが
一致する。

M4T keyはlength 16、`4d3454 || session_id:u32 || fingerprint[0..8]`。
Valueはversion 1、state 1 MINTEDまたは2 CONSUMED、bytes 2..3 zero、
同じsession ID、non-zero membership epoch、attachment epoch、hop context ID、
key generation、non-zero fingerprint[32]、CRC32C over bytes 0..67を持つ。
Key session/fingerprint prefixはvalueとexact一致する。

C3R keyはlength 16、
`433352 || hop_context_id:u32 || lane:u8 || layer_e2e:u8 ||
counter_low32:u32 || 000000`。Laneとlayerは各0/1。Valueはversion/state各1、
bytes 2..3 zero、同じnon-zero hop context、non-zero freshness epoch、同じlane/layer、
bytes 18..19 zero、non-zero counter、bytes 28..43 zero、CRC32C over bytes 0..43を持つ。
Key counter_low32はvalue counterのlow 32 bitとexact一致する。

NBS1 valueはmagic `4e42533100010000`、non-zero availability epoch、
bytes 16..18 zero、available byte 19が0/1、bytes 20..23 zero、non-zero clock epoch[16]、
now_ms:u64である。

#### 3.2 Status and scan precedence

Row classifierの優先順位はclosedである。

1. `(length>0 && data=NULL)`、alias、NULL outputは`NINLIL_E_INVALID_ARGUMENT`。
2. Exact current family/prefixを持つがlength、reserved、CRC、key/body bindingが不正なら
   `NINLIL_E_STORAGE_CORRUPT`。別classifierへfall throughしない。
3. Framing-validなknown future root/schema/versionは`NINLIL_E_UNSUPPORTED`。
4. Exact predicate一致はkindを返す。
5. どのclosed familyにも属さないrowは`NINLIL_E_UNSUPPORTED`。

「Framing-valid」はfamily共通のmagic、exact declared length、CRC、key/family bindingが
current framingとしてvalidであることを意味する。したがってCRC破壊、short/trailing、
declared length不一致は、version fieldがfuture値に見えても
`NINLIL_E_STORAGE_CORRUPT`を優先する。一方、CRC-valid
`binding_format=3`、NLR1 `record_version=2`、NTS3 `schema_major=2`、
M4T `version=2`は`NINLIL_E_UNSUPPORTED`である。Version 0はfutureではなくcorruptとする。

Namespace aggregateは`COMMIT_UNKNOWN > CORRUPT > MIXED > UNSUPPORTED >
EXACT_LAB > EXACT_DOMAIN > EMPTY`の順である。Canonical publicationは
`EXACT_DOMAIN`だけが次gateへ進める。`EXACT_LAB`はread-only exportだけ、
EMPTYはT0候補だけで、34-kind LAB gateのadopt successにはしない。

Machine-readable authority
`spec/vectors/domain-store-schema1-runtime-binding-v1.json`は34-kind isolated row
predicate catalogと、format 1 bootstrap/complete legacy metadata/cross-row companionをmaterializeした34
namespace-level `EXACT_LAB` positives、
各predicateへ要求するshort/long/magic/version/reserved/CRC/key-body mutation、
format 2 Domain + kind 20..34、format 1 + Domain semantic row、LAB/foreign mixtureの
vector IDと期待aggregate statusを列挙する。全34 kindについてisolated row positiveのexact
key/value bytesとnamespace positive fixture、key short/long、value short、value
integrity破壊の4 namespace mutation fixtureを固定し、
各mutationはrow=`NINLIL_E_STORAGE_CORRUPT`、namespace=`CORRUPT`、publish=falseである。
この136件を置換・弱化せず、format 1 authority absent/wrong、kind 18 metadata member
missing/digest mismatch、kind 20 `slot == max_services`、kind 30 matching NTS3
missing/transaction ID/payload/route mismatch、kind 33 runtime mismatchのexact **10**
namespace cross-row negativeを別集合へ固定する。Cross-row negativeのpresent rowは
codec単体では`NINLIL_OK`で、独立namespace oracleが`UNSUPPORTED`、`MIXED`、または
`CORRUPT`を導出し、固定booleanをexpected authorityにしない。
さらにmetadata境界7件をformat 1 0/16=`EXACT_LAB`、format 1
UNINITIALIZED/TRUSTED 16/16=`EXACT_LAB`、format 2 exact 17-row bootstrap +
0/16=`EXACT_DOMAIN`、format 2 UNINITIALIZED/TRUSTED 16/16=`EXACT_DOMAIN`、
format 2 15/16=`CORRUPT`として固定する。Format 2 0/16はT1a NEW / T1b OLDの
`FORMAT2_METADATA_ALL_OLD_ZERO_OF_16` transient stateで、17 unique keyと
namespace SHA-256を独立再計算し、
`transient=true`、`canonical_publish=false`のまま後続T1bへ渡す。他の初期化候補も
T2–T7完了前は`canonical_publish=false`である。
Constructible MIXED 18件はformat 2 exact bootstrap + kind 20..34の15件、format 1
binding/bootstrap row setを基礎にcapacity rowをkind-1 post-valueでoverlayして残る
distinct Domain post rowsを加える2件、format 1 exact bootstrap + foreign rowの1件である。
Same-key format 1/2 duplicateはこの18件から除外し、別のprovider-contract CORRUPT vectorに
固定する。
Production-independent row/namespace classifierは34 positive、136 mutation、
10 cross-row negative、7 metadata boundary、18 MIXED、provider duplicateの全fixtureを
actual key/value bytesから再分類する。Expected status文字列をoracle結果として採用せず、
row codec、binding authority、cross-row truth、closed precedenceの計算結果と一致させる。
Format 1 arithmetic fixtureはformat 1に実際にencodeされるfieldだけを持ち、Domain-only
profile ID/revision/minimum writer generation/rollback epochをunused fieldとして混入させない。
Generatorはproduction classifierをoracleとしてimportせず、format 1/2 bootstrap、NLR1、
NTS3、NEL1、NRV1、M4T、C3R、NBS1と固定済みkind-1 KATのbytes/statusをfield式から独立計算する。
`closed_status_oracle_vectors`はcurrent positive 3、framing-valid future 4、
malformed current 6のexact 13 raw KATを持つ。Python
`tools/domain_store_schema1_binding_gate.py`とNode.js
`tools/domain_store_schema1_binding_gate.mjs`はgeneratorをimportせず、raw key/value、
declared length、CRC32C、version/schema/formatを別実装で再計算する。両gateのself-testは
future fixtureのCRC破壊や期待status改変をfalse greenにしない。

### 4. Migrationはread-only exportとexplicit re-bootstrapだけ

LAB namespaceからDomain rowへのautomatic conversionは存在しない。Operator flowは次である。
V1 LABのservice markerはslotとmarker bytesだけで、accepted descriptor、SERVICE semantic
snapshot、quota window clock/start、window admissions/payloadをdurableに持たない。NTS3
transaction scanからactive inflightの一部を再構成できても、失われたwindow quota counterと
そのauthoritative sampleをlosslessに復元できない。したがってformat 1 rowからformat 2
SERVICE/QUOTA/RESERVATIONを合成することはmigrationではなく推測になり、禁止する。

1. 同じREAD_ONLY transactionを最後までiterateし、sourceを変更せずexportする。
2. Artifactをauthoritative business systemとoperatorがreconcileする。
3. 現在0-rowと判定された別namespaceを明示選択し、T1aから開始する。
4. Serviceをpublic APIで明示re-registerし、workを新規admitする。
5. Source archive/deleteはRuntime外の別authorizationとし、成功移行の証拠にしない。

#### 4.1 Exact export artifact v1

Artifactは次のunsigned big-endian binary framingである。

```text
magic                         8 = ASCII "NLEXP001"
format_version                u16 = 1
source_profile                u16 = 1  # V1 LAB
flags                         u32 = 0
provider_kind                 u16, 1..65535
provider_schema               u16, 1..65535
provider_identity_digest      32
namespace_length              u16, 1..255
namespace_bytes               namespace_length
record_count                  u32
for each row, key unsigned-byte lexicographic ascending:
  key_length                  u16, 1..255
  reserved                    u16 = 0
  value_length                u32, 1..65536
  key                         key_length
  value                       value_length
  row_digest                  32 = SHA-256(
    ASCII("NINLIL-LAB-EXPORT-ROW-V1") ||
    key_length:u16 || key || value_length:u32 || value)
content_digest                32 = SHA-256(
  ASCII("NINLIL-LAB-EXPORT-V1") || all preceding artifact bytes)
completion_magic              8 = ASCII "NLEXDONE"
```

`provider_kind`と`provider_schema`はintegrationが固定したsource providerの公開identityで、
zeroは禁止する。`provider_identity_digest`は次のcanonical SHA-256で、zeroは禁止する。

```text
SHA-256(
  ASCII("NINLIL-LAB-EXPORT-PROVIDER-V1") ||
  provider_kind:u16 || provider_schema:u16 ||
  provider_config_length:u16 || provider_config)
```

同一READ_ONLY
transactionでiterator exhaustionまで成功し、duplicate key 0、strict order、全row digest、
record count、content digestを確定した後だけcompletion magicを書く。途中file、
missing/duplicate/reordered row、digest/length/trailing byte mismatch、unknown format/flag、
0/unknown provider kind/schema、0 provider digestはinvalidであり、reconcile/import根拠にしない。
ArtifactはevidenceであってDomain Store import formatではない。Artifact全体の配布SHA-256は
sidecar/manifestにexact記録する。

Machine-readable authorityはexact bytesを持つpositive 2件（namespace/key/valueの各minimum、
およびnamespace 255/key 255/value 65,536のmaximum）とmutation 18件を固定する。
Truncate、missing completion、duplicate、reorder、row/content digest、declared length、
trailing、format/source/flag、row reserved、provider kind/schema/identity digestを各1条件ずつ
変える。Unknown format/source/flagとknown pair以外のnon-zero provider kind/schemaは
`NINLIL_E_UNSUPPORTED`、framing/order/digest/length/trailing/reserved違反とzero provider
fieldは`NINLIL_E_STORAGE_CORRUPT`である。Order/provider mutationはcontent digestまで
再計算し、別のdigest mismatchを期待理由にしない。

### 5. First kind-1 SERVICE_REGISTER group

T0–T7完了後の最初のunique service registrationはoperation kind 1で、memberはM=5。
Manifest entry orderは**complete keyのunsigned-byte lexicographic順**で固定する。

| Ordinal | Action | Exact member |
| ---: | --- | --- |
| 1 | REPLACE | family-4 capacity kind 1 `SERVICE` |
| 2 | CREATE | family-6 subtype `10` SERVICE |
| 3 | CREATE | family-6 subtype `11` SERVICE_QUOTA |
| 4 | CREATE | family-6 subtype `23` SERVICE owner RESERVATION |
| 5 | REPLACE | family-6 subtype `7d`、上記capacity keyのHEAD_INDEX |

Header/chunkはmemberに数えない。Exact post-stateは次である。

- 共通: semantic family 6 recordsはdomain format 1、flags 0、revision 1、
  head=`W`（新しいwitness composite identity）。SERVICE primary PVDはzero。
  QUOTA/RESERVATION primary PVDはcomplete SERVICE post-valueのSHA-256。
- SERVICE: bodyはcaller descriptorのcanonical snapshot、quota/reservation key digestを
  complete keyから再計算。Primary IDはSERVICE composite identity先頭16。
- QUOTA: `window_clock_epoch`はregistrationで固定したT5 trusted sample epoch。
  `window_start_ms = floor(now_ms / admission_window_ms) * admission_window_ms`をchecked計算し、
  admissions/payload/active transaction/active spool count/bytesは全zero。
- RESERVATION: owner kind=SERVICE、owner raw=service raw、primary key digest=complete SERVICE key。
  11-vectorはkind 1だけ`used=1,reserved=0`、kind 2..11は両方zero。
  `service_inflight=0`、grant count/bytes=0、released mask=0。
- Capacity kind 1: `limit`不変、`used=old.used+1`、`reserved`不変、
  `high_water=max(old.high_water, used+reserved)`、`capacity_epoch=old+1`、
  blocked/exhaustedは0。First registrationのold exact値はused/reserved/high-water=0、
  epoch=1、flags 0なのでpostはused=1、reserved=0、high-water=1、epoch=2。
- HEAD_INDEX: old BASELINEからWITNESSEDへrevision 2でreplaceし、member key/key digestは
  capacity kind 1、member value digestはcapacity post-value SHA-256、body/common headは`W`、
  primary PVDはzero。

`W = COMPOSITE(7f, operation_kind:u16=1 ||
RAW16(contents=service_complete_key_digest[32]))`で、operation identityはその32 bytes。
ACTIVE WITNESS_HEADERはsubject ID=`service_complete_key_digest[0..15]`、member count 5、
chunk count 1、retention kind 0/digest zero、successor zero、canonical digestは17章formula。
WITNESS_MANIFEST_CHUNKはindex 0/count 1/entry count 5で上表順、manifest digestは
そのcomplete chunk bodyから計算する。Header/chunk common revisionは1、primary ID=`W[0..15]`、
head/PVDはzeroである。Predecessor headerは0、全CREATE prior/old digestはzero、capacityと
HEAD_INDEXのold/new digestはexact非zero、HEAD_INDEX entry prior headはzeroである。

Kind-1 KATはmachine-readable authorityにdescriptor、trusted sample、old capacity/index、
全7 recordのkey/value hex、5 entry digest、W、manifest/canonical digest、FULL stage order、
aggregate SHA-256を固定する。Independent generatorはproduction C codecを呼ばず、
big-endian/CRC32C/SHA-256を再計算する。

さらにoracle専用fixture transcript
`ASCII("NINLIL-DOMAIN-KIND1-FIXTURE-V1") || manifest entries ||
pre rows || post rows`へactual entry/key/value bytesを格納し、positive 1件と
missing member、extra member、no-op REPLACE、wrong manifest orderのnegative 4件を固定する。
各negativeはheader/chunk、manifest digest、canonical operation digestをmutation後のbytesから
再構築した上で`NINLIL_E_STORAGE_CORRUPT`となる。Fixture transcriptはRuntimeの
storage/wire/import形式ではない。
全fixtureのsemantic pre/post rowはmember count判定より前に、production Cを呼ばない独立D1
row-local oracleでcomplete key、NLR1/CRC/common header、subtype body、key/body identityを
再計算して全件`NINLIL_OK`を要求する。Extra memberはalternate kind-1 fixture
（application ID=`0x12`×16、service=`valve`、descriptor digest=`0x23`×32）のrow-local
valid SERVICE `0x10` body/keyを使い、common headだけを当該fixtureのcurrent `W`へencodeする。
空body、別のlocal codec違反、digest mismatchをextra-member rejection理由へ混入させない。

Positive M=5のentry/action/digest検査後には、同じraw fixture bytesとpinned trusted-clock
inputからgroup semantic oracleを実行する。SERVICE↔QUOTA/RESERVATION PVD、quota
epoch/window/全zero counter、RESERVATION 11-vector/counter、capacity old→post +1、
HEAD_INDEX member digest/headを再計算する。Machine authorityは従来4 negativeに加え、
quota PVD、quota counter、quota window、reservation PVD、reservation vector、
capacity increment、HEAD_INDEX value digestを各1条件だけ変えた7 negativeを持つ。
全7件はD1、M=5、NLR1 CRC、entry digest、manifest、headerがvalidなままgroup semantic
reasonでrejectされる。

#### 5.1 Kind-1 COMMIT_UNKNOWN and reattach

Unknown後のauthoritative classificationは次だけである。

| Result | Durable truth | Volatile/public result |
| --- | --- | --- |
| ALL_OLD | 3 CREATE target absent、capacity/index exact pre-value、header/chunk absent | handle/callback/send 0。同じlogical requestだけ明示retry可 |
| ALL_NEW | 5 post member、ACTIVE header、chunkがbyte/digest/cross-row exact | **handle/callbackはなお0**。Mutationの再実行禁止 |
| MIXED/other | missing/extra/third value、partial header/chunk、digest/order mismatch | corrupt/fenced、mutation/handle/callback/send 0 |

ALL_NEWはdurable adoptionだけで、失われたcallback pointer/user pointerを復元しない。
Callerが後で同じSERVICE semantic descriptorと新しいcallback setを使って
`register_service`を明示再実行した場合だけ、exact existing reattachとしてdurable write 0で
新しいhandleを返せる。Descriptor conflict、別service key、automatic callback invocation、
automatic slot publicationは禁止する。

### 6. Public publication remains red until T0–T7

```text
T0 fresh READ_WRITE pre-mutation full scan: namespace 0 row
 -> T1a format-2 17-row bootstrap
 -> T1b 16-row UNINITIALIZED metadata
 -> T2 D3-S4..S12 cross-row validation
 -> T3 D4 recovery mutation + fresh re-scan
 -> T4 identity exact/forward-rotation recovery
 -> T5 trusted clock transition + fresh re-scan
 -> T6 durable health reconstruction
 -> Bearer open
 -> metrics entropy
 -> T7 public Runtime publish gate
```

この順序はCanonical Domain profileの唯一のcreate順である。旧
`recovery -> Bearer open -> clock`順をCanonical pathへ適用しない。Machine-readable
startup transcriptはstorage recovery、trusted clock/T5、health/T6、Bearer open、entropy、
publishを各境界で1つずつfaultさせる。特にT2、T3、T4、T7は独立fixtureであり、
`storage_recovery_T0_T4`のようなaggregate 1件へ畳まない。T5/T6完了前のBearer/
callback/handle/publish exact 0と、T7完了前のcallback/handle/publish exact 0を再計算する。

Existing/retry/`COMMIT_UNKNOWN` classificationだけはfresh `READ_ONLY` transactionを使う。
そこでT1a OLDを確認してもmutationへupgradeせず、fresh `READ_WRITE` transactionの
pre-mutation full scanで0-rowを再証明してから同じtransaction内のT1aへ進む。

T7はfamily 1–6 full scan、15 HEAD_INDEX、CLOCK、primary/index/backlink/witness、
4 counter、11 capacity、unresolved old/new group exact 0、identity、clock、health、
Storage priority 1/2 reference 0、transaction/iterator 0、exclusive handle 1を全て要求する。
Private seamの`storage_recovery_complete`、LAB restart、codec単体、metadata write成功は
どれもT7をgreenにしない。

### 7. Rejected alternatives

| 案 | 不採用理由 |
| --- | --- |
| Format 1をDomainでも継続利用 | 最後のLAB binaryがDomain rowを同じprofileとして誤認し、rollback fenceにならない |
| READ_ONLYでempty確認後、別READ_WRITEへ移る | 2 snapshot間の競合を採用authorityから除外できない |
| LAB rowをその場でautomatic migration | quota、callback、custody/effect truthをlosslessに再構築できない |
| T0–T4またはT2–T7を単一success bit/KATへ集約 | individual stage skipとpremature publishを検知できない |
| LAB quarantine classifierをCanonical publication authorityにも使う | recognized LAB evidenceとvalid Domain truthの意味が異なる |
| 先にBearerをopenし後でclock/recoveryを完了 | 外部I/Oを未確定durable identity/stateへ結び、failure domainを破る |

### 8. S1–S6 normative trace

| Gate | 本ADRの根拠 | 状態 |
| --- | --- | --- |
| S1 Scope/decision | Context、Scope/owner/failure domain/dependency、D22-01..08、Rejected alternatives | 記述済み |
| S2 Allocation | §1.1 format 2 exact bytes/profile/revision/generation/epoch/schema、§3、§4 export | 記述済み（採番はProposed） |
| S3 Normative form | §1–§6のT0–T7、FULL ordering、classifier precedence、bounded artifact/kind-1 contract | 記述済み |
| S4 KAT/oracle | machine JSON、generator、Python/Node independent gate、13 closed-status KAT、13 startup KAT、各self-test | docs evidence記述済み |
| S5 Compatibility/nonclaim | §4、Compatibility and non-claims、format 1/2 downgrade、explicit re-bootstrap | 記述済み |
| S6 Review | 本traceとD22 decision registerをreview入力とし、独立reviewでP0/P1=0、ADR index/参照整合を確認 | **OPEN — Acceptedにしない** |

Normative requirement traceは、`D22-02`→Acceptance 1、
`D22-03`→Acceptance 2、`D22-01`→Acceptance 3、
`D22-04`→Acceptance 4、`D22-05`→Acceptance 5、
`D22-08`→Acceptance 6–7、`D22-06`→Acceptance 8、
public ABI非変更→Acceptance 9、`D22-07`→Acceptance 10である。Machine authorityは
`spec/vectors/domain-store-schema1-runtime-binding-v1.json`、freshness authorityは
generator `--check`、独立意味検査はPython/Node gate `--check`、false-green検査は各
`--self-test`である。S6がOPENの間は本ADRをAcceptedまたはimplementation-readyと表示しない。

## Compatibility and non-claims

- Public `NINLIL_ABI_VERSION=0x0001`、public struct/offset、single Bearer contractは不変。
- Private binding format 2、classifier、export、kind-1 builderは未実装である。Docs-onlyの
  独立vector generator/KATはproduction supportまたはRuntime実装の証拠ではない。
- Format 1 LAB namespaceのread-write open、automatic conversion、ID/callback/custody/effectの
  preservation、archive/delete tool、production supportを約束しない。
- 本ADRは**Proposed**であり、Accepted/D3/D4/Stage 5/public Runtime completion evidenceではない。

## Acceptance tests for a future implementation

1. T0はfresh READ_WRITE transactionのmutation前同一snapshotの0-rowだけ。別READ_ONLY
   transactionからのupgrade、1 unknown row、scan error、concurrent changeはwrite 0。
2. T1a/T1b/T5の各fault pointで、次createは表のOLD/NEWだけを採用しpartial/thirdをfenceする。
   Machine KATはT1a 6件、T1b 6件、T5 5件のfull snapshot bytes、snapshot digest、
   read-only classification transcriptを持つ。
3. Format 2 bindingへ最後のLAB binaryを向け、publish 0かつREAD_WRITE transcript 0を証明する。
   Unknown format/profile ID、revision、minimum writer、rollback epoch、schemaもCRC-validな
   single-cause bytesで`NINLIL_E_UNSUPPORTED`を証明する。
4. Canonical binaryにLAB publication gate symbol/callがなく、34-kind isolated row /
   namespace positive / 136 namespace mutation / 18 constructible MIXED vectorsと、
   10 namespace cross-row negative、7 metadata all-old/all-new/trusted boundary、
   same-key duplicate provider-corruption vectorが期待statusと一致する。Kind 18/19
   namespace positiveはformat 1 bootstrap + complete
   15 BASELINE index + 1 valid clockであり、partial metadataをsuccessにしない。
5. Exportは同一snapshot全rowをstrict orderで含みsource bytesを変更しない。Exact
   positive 2件とmutation 18件についてbytes、artifact SHA-256、row/content digest、
   statusを再計算し、truncate、reorder、duplicate、digest/length/trailing corruption、
   missing completion、format/source/flag/reserved、0/unknown provider kind/schema、
   0/mismatch provider identity digestをrejectする。
6. Kind 1 KATはcapacity→SERVICE→QUOTA→RESERVATION→HEAD_INDEXのM=5と全post値を再計算し、
   actual fixture bytesを持つpositive 1件 / negative 11件で、extra/missing/no-op/wrong orderと
   7件のcross-row semantic mismatchをrejectする。
7. Kind-1 `COMMIT_UNKNOWN` ALL_NEW直後もhandle/callback 0。後続exact explicit reattachだけが
   write 0でhandleを作る。
8. T2–T7を1条件ずつredにし、`runtime_create()` publish 0を証明する。
9. Installed public header ABI diffは0。
10. CRC-valid `binding_format=3` / NLR1 `record_version=2` /
    NTS3 `schema_major=2` / M4T `version=2`は各`NINLIL_E_UNSUPPORTED`、同じfamilyの
    short/CRC mismatchは各`NINLIL_E_STORAGE_CORRUPT`となる。Exact 13 raw KATを
    PythonとNode.jsの独立oracleで再分類し、両self-testのmutationが必ずredになる。

## Related

[17章: Foundation Domain Store v1](../17-foundation-domain-store.md) ·
[12章: Foundation C ABI](../12-foundation-abi.md) ·
[13章: Foundation State Machine](../13-foundation-state-machine.md) ·
[34章: Runtime Fabric Completion Contract](../34-v2-runtime-fabric-completion.md)
