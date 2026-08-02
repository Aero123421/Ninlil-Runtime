# ADR-0028: Composable Public Runtime Modules

- Status: **Proposed**
- Date: 2026-07-30
- Supersedes: none
- Refines: ADR-0017, ADR-0018, ADR-0019, ADR-0020, ADR-0021
- Independent review: **NO-GO reflected; re-review pending**

## Context

Ninlil の Portable Core は複数の application Service を同じ Runtime に登録
できる。一方、Fabric、Wi-Fi、route/relay、multi-parent、R7 fragmentation、
multi-frame durable transfer は source-private / default-OFF の候補であり、
install 済み SDK の利用者は正規の header と CMake target から利用できない。

個別候補の Host test が合格しても、それだけでは汎用 OSS SDK ではない。逆に、
全機能を `Ninlil::runtime` の単一 ABI へ直接追加すると socket、TLS、radio、
route authority、転送方式が Portable Core へ逆流し、小さな組み込み構成を壊す。

物理 node は単一の製品 role へ固定されない。同じ node が複数 application
Service と relay behavior を同時に持てる必要がある。ただし application Service
と transport behavior は別の関心であり、単一 role enum へ混ぜない。

現 private 実装には process-global owner、scratch、seam があり、同じ process の
複数 Runtime / 複数親機を安全に構成できる public contractにはなっていない。
また、Fabric が RRMP private hook を直接知る依存逆転、POSIX/ESP型の混在、
compile definitionでlayoutが変わる R7 engine、未AcceptedのRF mappingがある。
private headerをそのままinstallする方針は採らない。

## Decision

### 1. ADRの採用範囲とmodule状態を分ける

本ADRが将来 Accepted になっても、それは「高度機能を独立した composable public
moduleとして提供する構造」の採用だけを意味する。個々のmoduleがpublic/release対応
したとは意味しない。

moduleごとに次の `module_api_state` をmachine-readable manifestへ記録する。

```text
PRIVATE_CANDIDATE
PUBLIC_API_SPEC_ACCEPTED
PACKAGE_EXPERIMENTAL
RELEASE_SUPPORTED
```

遷移は次の一本だけで、履歴から状態を消す、飛び越す、巻き戻すことを禁止する。

```text
PRIVATE_CANDIDATE
  -> PUBLIC_API_SPEC_ACCEPTED
  -> PACKAGE_EXPERIMENTAL
  -> RELEASE_SUPPORTED
```

`PACKAGE_EXPERIMENTAL`はinstall可能だがproduction supportを意味しない。
`RELEASE_SUPPORTED`だけが対象platformでの安定公開を表す。moduleを
`RELEASE_SUPPORTED`へ進めるには、そのmoduleが列挙した全platformと全
completion featureが、別domain側でもexact `RELEASE_SUPPORTED`でなければならない。
Host合格をESP completionへ、compile/linkをHILへ丸めない。

この4状態は[34章 §3](../34-v2-runtime-fabric-completion.md)と
`compatibility-matrix.json`の7状態
`completion_state`とは**直交する別domain**である。例えば、private実装がHost testに
合格してもmodule APIは`PRIVATE_CANDIDATE`のままであり、module packageが
`PACKAGE_EXPERIMENTAL`でも対象featureを`RELEASE_SUPPORTED`とは呼ばない。

4状態から7状態への昇格条件は推測せず、次のexact mappingを使う。

| `module_api_state` | mapped feature / dependency closure | package | acceptance |
| --- | --- | --- | --- |
| `PRIVATE_CANDIDATE` | floorなし。completionが先行してもよい | `ABSENT` | 実装acceptanceを要求しない |
| `PUBLIC_API_SPEC_ACCEPTED` | 全mapped featureと明示dependency closureが最低`SPEC_ACCEPTED` | `ABSENT` | public ABI、port、resource、dependency仕様がAccepted |
| `PACKAGE_EXPERIMENTAL` | `PUBLIC_API_SPEC_ACCEPTED`のfloorを維持 | `PRESENT` | 当該moduleのnon-HIL acceptanceが全て`PASS` |
| `RELEASE_SUPPORTED` | 全mapped feature、dependency closure、対象platformがexact `RELEASE_SUPPORTED` | `PRESENT` | 全acceptanceとrequired HILが`PASS` |

`PACKAGE_EXPERIMENTAL`を`HOST_CANDIDATE`、`TARGET_CANDIDATE`、または
`HIL_VERIFIED`へ自動変換しない。逆方向も同様で、completion stateが高くても
module API stateは履歴を一段ずつ進める。machine-readableな同一表は
`public-module-manifest.json#/module_api_completion_mapping`を正本とする。

正本は次のclosed setとする。

| Authority | Exact path / value |
| --- | --- |
| Module manifest | `public-module-manifest.json` |
| Schema | `spec/public-module-manifest-v1.schema.json` |
| Schema ID/version | `ninlil-public-module-manifest-v1` / `1` |
| State index | `compatibility-matrix.json#/module_api_domain` |
| Completion state | `compatibility-matrix.json#/completion_states`、`#/features` |
| Gate | `python3 tools/public_module_manifest_gate.py check` / `self-test` |

unknown key、unknown state、unknown schema version、重複JSON key、非有限数はfail closedと
する。manifestの`state_history`を遷移証拠とし、release時は以前のrelease manifestとの
immutable diff gateも追加する。

ADR decision stateは先頭H1、空行、3行目のcanonical metadata lineからのみ読む。
H1はexact `# ADR-0028: Composable Public Runtime Modules`へbindする。
HTML comment、引用、inline/fenced codeに置いた別state、重複metadata lineを採用しない。
これにより本文やcode例へ`Accepted`相当の文字列を足しただけでは昇格できない。

各moduleは`promotion_authority`にmodule固有の`docs/modules/*-v1.md`と独立review artifact
を持つ。`PUBLIC_API_SPEC_ACCEPTED`へ進めるには、module固有仕様のcanonical decisionが
Accepted、reviewがimmutable candidateの40桁commit SHAへbindしたGO、P0/P1/P2がすべて0、
review bytesのSHA-256、検証済みreviewer provenanceとimplementer separationが一致しなければ
ならない。offline verifierが無い現在はGO自体を拒否する。promotion commitはcandidateのexact
single childとし、manifest/matrix/review/evidence以外を変更しない。本ADRのAccepted、
共通ADR、実装testのPASSをmodule固有
仕様またはreviewの代用にしない。現時点では全moduleの仕様は`NOT_CREATED`、reviewは
`NOT_RUN`である。

現時点の初期値は次のとおり。

| Module | Initial state | Normative dependency | Platform boundary |
| --- | --- | --- | --- |
| Fabric v1 | `PRIVATE_CANDIDATE` | ADR-0017 | portable C |
| Wi-Fi common v1 | `PRIVATE_CANDIDATE` | ADR-0018 | portable static archive |
| Wi-Fi POSIX v1 | `PRIVATE_CANDIDATE` | ADR-0018 | POSIX target |
| Wi-Fi ESP v1 | `PRIVATE_CANDIDATE` | ADR-0018 | ESP component |
| Route/Relay v1 | `PRIVATE_CANDIDATE` | ADR-0019, ADR-0020 | portable C + caller ports |
| Radio Fragmentation v1 | `PRIVATE_CANDIDATE` | R7 fragmentation specs | pure portable engine |
| Radio Fabric Adapter v1 | `PRIVATE_CANDIDATE` | separate Accepted NFL1↔R7↔NRW1 mapping | Fabric/radio adapter |
| MFDT v1 | `PRIVATE_CANDIDATE` | ADR-0021 | portable manager + carrier ports |

各依存ADRが Proposed のmoduleは `PUBLIC_API_SPEC_ACCEPTED`へ進めない。現時点では
**全moduleが`PRIVATE_CANDIDATE`**であり、本ADRが独立再レビューGOになるまでpackage/public
header/public targetを先行追加しない。

manifestの`dependencies[].enforced_from_owner_module_state`はdependency側moduleの状態ではなく、
**このdependency floorを所有moduleのどのAPI状態から強制するか**を表す。本v1 manifestでは
全て`PUBLIC_API_SPEC_ACCEPTED`である。`precondition_contract_id`はcompletion featureを
どのversioned Core/Foundation runtime bindingで満たすかを示し、package component IDではない。
package module同士の依存状態は`package.dependencies`で別に検査する。

### 1.1 Identity、Membership、Attachment/sessionのCore/Foundation precondition

`identity-attachment-session-install`はoptional package moduleではなく、network stateを
利用するpublic moduleがavailabilityへ進む前に満たすCore/Foundation preconditionとする。
package discoveryで架空のIdentity componentを探したり、completion feature名だけから
session authorityを推測したりしない。

正本contract IDは`ninlil_identity_attachment_precondition_v1`、provider port IDは
`ninlil_identity_attachment_provider_v1`、ABI versionはexact `1`である。次のmoduleは
Identity feature dependencyに同contract IDを明記する。

| Required | 理由 |
| --- | --- |
| Fabric、Wi-Fi common/POSIX/ESP | path/link availabilityを認証済みidentityとactive sessionへbindする |
| Route/Relay、Radio Fabric Adapter | owner/peer/contextをactive membershipとAttachmentへbindする |
| MFDT | durable transfer carrierとkey usageをactive sessionへbindする |

pure `radio_frag_v1`はidentity、session、I/Oを所有しないbounded byte transformなので
このpreconditionから除外する。pure engineへproviderやkey handleを持ち込まない。

provider descriptorはmodule create時にcopyする。binding取得結果は次をcopy-owned metadata
として返し、opaque binding/key handleだけをprovider-ownedとする。

- provider、Runtime、module、bindingの各16-byte instance IDと`u64` generation
- stable identity ID、credential revision、identity binding digest
- membership authority ID、membership epoch、membership-set digest
- Attachment ID/generation、session ID/generation、security context ID/epoch
- expiry authority ID/epoch、not-before、expiry、invalidation epoch
- provider ID/generation、key handle ID/generation、usage maskだけを持つ
  `ninlil_nonexporting_key_handle_v1`

private scalar、raw secret、raw session keyはpublic moduleへexportしない。key operationは
provider callbackで実行し、usage maskを検査してoperation resultだけを返す。non-success時は
出力をzeroizeして長さ0を返す。partial output、provider mismatch、usage mismatchは
fail closedとする。

provider portは`resolve_binding`、`validate_binding`、`perform_key_operation`、
`release_binding`、`subscribe_invalidation`、`unsubscribe_invalidation`をfield順付きの
version/size C ABIとして提供する。callback inputはcall中だけ有効で保持禁止、provider
contextはunsubscribeとcallback drain完了まで有効、owner execution context上で直列化し、
同じprovider/moduleへの再入は`NINLIL_E_REENTRANT`で拒否する。

6 callbackはすべて
`ninlil_status_t (*)(void *context, const <request-v1> *, <result-v1> *)`
の別typedefとし、request/resultを`void *`へ丸めない。provider descriptor、
binding snapshot、opaque binding handle、non-exporting key handle、subscription handle、
resolve/validate/key-operation/release/subscribe/unsubscribeの全request/result、
invalidation eventのfield順は
`public-module-manifest.json#/identity_attachment_precondition_contract/provider_port`
をexact machine authorityとする。全descriptor/request/result/eventは
`u32 abi_version + u32 struct_size`でexact ABI 1、v1最終fieldまでをminimum prefixとする。
inputの未知trailing bytesは読まず保持せず、short outputはknown outputをzero化して
`NINLIL_E_BUFFER_TOO_SMALL`、opaque handleはexact v1 size、reserved/nonzero unknown flag、
unknown enum、unknown provider statusはmutationなしでfail closedとする。

key usageはAUTH tag/verify、AEAD seal/open、digest sign/verifyの6 bit（allowed mask
`0x3f`）だけで、0または未知bitを拒否する。key handle flagはnon-exportable、
provider-bound、session-boundの3 bit（required/allowed mask `0x07`）をすべて要求し、
未知bitはhandleを無効化する。operationとusage bitは1対1で、verify operationをsealへ、
signをraw key exportへfallbackしない。non-success、unknown status、partial outputでは
providerが既に書いたoutputもzero化し長さ0にする。

`verified`、`released`、`callbacks_drained`はCの`u32` booleanで、known domainはexact
`0/1`だけとする。invalidation eventの`changed_floor_mask`はprovider、credential、
membership、Attachment、session、security、expiry、invalidation、binding handle、keyの
10 bit（allowed mask `0x03ff`）で、0または未知bitを拒否してbindingをfenceする。
key-operation requestにはverification入力を曖昧にしない
`authenticator/authenticator_size`を持たせ、各6 operationのnonce/AAD/input/
authenticator/output/verifiedの必須・禁止・上限とauthentication failure status 19を
manifestでexact化する。`bool`をJSON integer 0/1として受理する実装は禁止する。

availabilityのlinearizationは`resolve -> validate -> subscribe -> publish`である。
subscribe失敗時はpublishせずbindingをreleaseしてlocal handleをzero化する。shutdownは
admission/send fence、key operation drain、unsubscribe、invalidation callback drain、
binding release、provider copy releaseの順である。unsubscribe失敗時は
`FENCED_CLOSING`に留まり、provider context/subscription/bindingを保持してunsubscribe retry
以外を拒否する。releaseを先行してuse-after-freeを作らない。

moduleはadmission前とsend前にprovider validationを行う。not-before未到達、expiry
`now >= expires_at`、revoked、superseded、identity/membership/Attachment/session/security/key
generation不一致では新規処理を開始せず、inflight使用もinvalidation callbackが返る前に
fenceする。tick値はmoduleにとってopaqueで、expiry authorityにbindしたprovider validation
だけが比較する。unknown/short ABI、zero/mismatched ID、cross/stale handle、
generation/epochのrollback・wrap、provider unavailable、reentry、partial outputも
fail closedである。forward gapはfresh provider resolveでauthoritative snapshotを得て
全旧handleを無効化した場合だけ許容し、見逃した更新を理由にavailabilityへfallbackしない。

restart時に永続化できるのはnon-secret ID/digestとmonotonic floorだけで、provider context、
binding handle、key handleを保存・再利用しない。floorのwriterはCore/Foundation Domain
Storeのsingle writerで、各optional moduleのprivate storeへ複製しない。durable recovery後にfresh resolveし、
credential revision、membership epoch、Attachment/session/security/expiry/invalidation、
provider/binding/key generationの各floor以上であることを確認するまでavailabilityを公開しない。

restart floorはmagic `NIAF`、schema 1の
`ninlil_identity_attachment_floor_checkpoint_v1`という1つのFULL logical recordへ
canonical little-endianで保存する。realm/Runtime/module/provider/identity authorityと全floor、
checkpoint generation、payload digest、CRC32Cを同じsingle-writer atomic commitに含める。
multi-key partial checkpointは禁止する。`COMMIT_UNKNOWN`はexact keyのauthoritative readで
generationとdigestが一致した場合だけcommit済みとし、それ以外は最後に証明済みのFULL
recordからretryする。torn、CRC/size/digest不一致、未知magic/schema、複数current候補、
generation wrapはavailabilityとkey useをfenceし、古いhandleへのfallbackを禁止する。
recordはexact 308 bytes。SHA-256はoffset 0から272 bytes
（magicからcheckpoint generation）をcoverageとし、digestをoffset 272へ32 bytes格納する。
CRC-32C/Castagnoliはnormal polynomial `0x1EDC6F41`、reflected
`0x82F63B78`、init/xorout `0xffffffff`、refin/refout trueでoffset 0から304 bytesをcoverage、
offset 304へlittle-endian 4 bytesで格納する。別CRC、多項式、coverage、byte order、
trailing byteを受理しない。

受入`PM-IDENTITY-PRECONDITION-2X2-01`は、required moduleごとにexact 2 Runtime + 2 distinct
module instanceを2 provider instanceへ`R0-M0-P0-B0`、`R1-M1-P1-B1`でbindする。cross
Runtime/module/provider handle、全stale generation、expired/revoked/superseded、
各monotonic rollback、restart前handleを負例とし、state mutation、send、key exportが
全て0であることを検査する。machine-readableなfield順、ownership、failure set、test/evidence
台帳は`public-module-manifest.json#/identity_attachment_precondition_contract`を正本とする。

昇格時は、`PUBLIC_API_SPEC_ACCEPTED`で本precondition contractとcompletion featureが
最低`SPEC_ACCEPTED`、`PACKAGE_EXPERIMENTAL`で当該moduleのnon-HIL acceptanceがprovider
2×2とfail-closed negativesを含み`PASS`、`RELEASE_SUPPORTED`で
`PM-IDENTITY-PRECONDITION-2X2-01`とcompletion featureがともに
`RELEASE_SUPPORTED`条件を満たす。1 moduleのlocalhost成功やcompile/linkだけで
precondition acceptanceを代用しない。

### 2. 公開SDKはoptional moduleにする

Portable Core は `Ninlil::runtime` のまま維持し、高度機能は別targetとする。

| Component | CMake / ESP-IDF surface | Installed header root | Responsibility |
| --- | --- | --- | --- |
| Fabric v1 | `Ninlil::fabric_v1` | `ninlil/fabric/v1/` | packet-link registry、canonical NFL1、path selection |
| Wi-Fi common v1 | `Ninlil::wifi_v1`（portable `STATIC_ARCHIVE`） | `ninlil/wifi/v1/` | platform-neutral config/status/callback contract |
| Wi-Fi POSIX v1 | `Ninlil::wifi_posix_v1` | `ninlil/wifi/v1/posix/` | TCP/TLS packet-link、POSIX reconnect lifecycle |
| Wi-Fi ESP v1 | ESP component `ninlil_wifi_v1` | `ninlil_esp_idf/wifi/v1/` | ESP STA/LwIP/mbedTLS adapter |
| Route/Relay v1 | `Ninlil::route_relay_v1` | `ninlil/route/v1/` | relay lifecycle、multi-parent authority/failover |
| Radio Frag v1 | `Ninlil::radio_frag_v1` | `ninlil/radio/frag/v1/` | bounded fragmentation/reassembly only |
| Radio Fabric Adapter v1 | `Ninlil::radio_fabric_adapter_v1` | `ninlil/radio/fabric/v1/` | Accepted RF mappingを使うpacket-link adapter |
| MFDT v1 | `Ninlil::mfdt_v1` | `ninlil/mfdt/v1/` | durable multi-frame transfer manager |

`Ninlil::runtime` はこれらをlink必須にしない。default Core archiveへoptional
module symbol、socket、TLS、FreeRTOS、mbedTLS、radio driverを混入させない。

公開headerはprivate workspace、fault seam、test hook、native TLS/RTOS object、
compile-time可変配列を露出しない。公開instanceはopaque handleまたはcaller-owned
opaque workspaceを使い、`workspace_required(profile_id)`で必要量とalignmentを返す。
Wi-Fi commonは`INTERFACE` targetではなくportable static archiveに固定し、POSIX targetは
exact `fabric_v1;wifi_v1`へ依存する。common archiveはsocket、OpenSSL、LwIP、
FreeRTOS、ESP header/symbolへ依存してはならない。

### 3. 依存方向

依存DAGを次へ固定する。

```text
Portable Core
  `- Fabric v1
       |- Wi-Fi POSIX/ESP packet-link adapter
       |- Route/Relay v1 observer
       |- Radio Frag v1 adapter
       `- MFDT Foundation carrier
```

- Fabric は RRMP、Wi-Fi、R7、MFDT の具体型やsymbolをinclude/callしない。
- Route/Relay側がmodule-neutralなFabric observer/selection portを登録する。
- Wi-Fiとradioはpacket-link portとしてFabricへ登録する。
- MFDTはFoundation carrier portを介し、Fabric自体へ転送stateを持ち込まない。
- optional module間の相互作用はversioned public callback/portだけを使う。

Route/RelayとFabricの依存逆転に使う最小C ABIを次で固定する。これは型名とfield順を
含むv1 shapeであり、private RRMP型を埋め込まない。

```c
typedef struct ninlil_fabric_observer_event_v1 {
    uint32_t abi_version;          /* exact 1 */
    uint32_t struct_size;          /* prefix compatibility */
    uint8_t owner_instance_id[16];
    uint64_t owner_generation;
    uint8_t subject_instance_id[16];
    uint64_t subject_generation;
    uint32_t event_kind;
    uint32_t flags;
    const uint8_t *payload;
    size_t payload_size;
} ninlil_fabric_observer_event_v1_t;

typedef ninlil_status_t (*ninlil_fabric_observer_on_event_v1_fn)(
    void *context,
    const ninlil_fabric_observer_event_v1_t *event);

typedef struct ninlil_fabric_observer_v1 {
    uint32_t abi_version;          /* exact 1 */
    uint32_t struct_size;          /* prefix compatibility */
    void *context;
    ninlil_fabric_observer_on_event_v1_fn on_event;
} ninlil_fabric_observer_v1_t;
```

登録はobserver内容をcopyし、`owner_instance_id + owner_generation`へbindしたopaque
registration handleを返す。callback inputはcall中だけ有効で保持禁止、callbackは同じ
Fabric instanceへ再入不可（`BUSY`）、unknown `event_kind`はmutationせず無視、
unregisterは既発callbackをdrainしてからgenerationを無効化する。NULL callback、
古い/別instance handle、短い`struct_size`、unknown `abi_version`はfail closedとする。
path selectionを変更するportはobserverと同じversion/size/identity/lifetime規則を持つ
別`ninlil_fabric_selection_port_v1`とし、observer callbackの戻り値を暗黙のroute
overrideに使わない。exact machine shapeはmanifestの`inter_module_port_contract`に置く。

selection callbackはpacket request、1 candidate、resultの3つのversion/size型を受ける。
requestはFabric/selector/selection-authorityのID+generation/epoch、policy revision、
packet/peer、size、deadline、capability、security、energy、compliance permitを持つ。
candidateはpath owner/path ID+generation、kind、capability、security、MTU、queue、
health、energy、base score、permitを持つ。resultは全authority echo、policy revision、
path ID+generation、`REJECT`/`ELIGIBLE`、bounded score adjustmentだけを返し、直接send、
未列挙path指定、authority変更を許さない。

security profileはnone/authenticated/confidential+authenticated/
hardware-bound confidential+authenticatedのexact 0..3と互換表、path kindはUSB CDC、
Wi-Fi、SX1262、POSIX loopback、registered otherのexact 1..5、healthはhealthy/degraded/
unavailableのexact 1..3とする。request/candidate/result flagsのallowed maskはすべて0。
base scoreとadjustmentは各`[-1000000,1000000]`、signed 64-bit加算結果は
`[-2000000,2000000]`でなければならない。unknown enum/bit、範囲外score、
unavailable pathはcallback前またはresult検証時に全selectionを送信0で拒否する。

最終eligibility再検査、score、tie-break、resource reservation、sendはFabricだけが行う。
selection authority/policy/path/permitのstale、別Fabric/selectorのrequest/candidate/result/
registration handle、callback error、unknown status/verdict/flag、partial result、全candidate
rejectは**送信0**でfail closedとする。callback再入は`NINLIL_E_REENTRANT`、
unregisterは新規selection停止、callback drain、registration generation無効化、
port copy解放の順である。exact field orderとfailure semanticsは
`public-module-manifest.json#/fabric_selection_port_contract`を正本とする。

### 4. instance ownershipと複数Runtime

すべてのpublic moduleはinstance-firstとし、暗黙のprocess-global current owner、
global registry、global mutable scratch、global default seamを使わない。

各module contractは次を固定する。

1. `workspace_required/create/close/destroy` と部分初期化時のrollback。
2. owner execution context、thread affinity、reentrancy、callback lifetime。
3. instanceごとのbounded queue、inflight、scratch、diagnostics。
4. module instanceとRuntime instanceのbinding handle。暗黙global lookupは禁止。
5. storage namespace、schema、writer fence、aggregate reservation。
6. 1つのphysical radio/Wi-Fi driverを所有するdriver-ownerと、その下のbounded demux。
7. 複数instanceが同時に存在する場合のfair schedulingとresource exhaustion。
8. destroy後または別instanceのhandle/cookieを使うcallのfail-closed rejection。

公開trancheの最小multi-instance受入はexact **2 Runtime instance + 同一moduleの2
module instance**である。bindingは`R0-M0`と`R1-M1`を正とし、`R0-M1`、`R1-M0`、
destroy後generation、instance IDだけ同じでgenerationが異なるhandleを負とする。
各moduleについて同じmatrixを実行し、1つのFabricだけを2回参照した試験を「2 module
instance」と数えない。

durable module instanceはcallerが与える
`realm_id[16] + physical_namespace + partition_prefix + module_instance_id[16] +
module_generation`で所有権を固定する。同一physical storeを共有する場合もrealmまたは
partitionが分離され、writer fenceはinstance IDとgenerationへbindする。alias、
prefix collision、writer二重取得、rollback generationはopen前に拒否し、暗黙のdefault
realmや自動prefixを作らない。

physical radio/Wi-Fi driverごとのownerはexact 1 instanceとする。他moduleは
`owner_instance_id + owner_generation + child_instance_id + child_generation`へbindした
bounded child handleだけを使い、2番目のowner取得とdirect driver accessを拒否する。
parent aggregate resourceは子を開始する前に`reserve -> commit`し、どれか1つでも
reserve不能なら子を1つも可視化せず全量releaseする。正常時はstrict round-robin
one-quantum、停止時はcallback drain後にchild、parent reservationの順で解放する。
このexact 2×2、storage、driver、aggregate authorityはmanifestの
`multi_instance_acceptance_contract`と`PM-COMPOSITION-2X2-01`へ固定する。

同一physical nodeは1つ以上の application Runtime と0個以上の transport moduleを
所有できる。

- 表示、event、sensor、request、responseは複数 application Serviceとして登録する。
- relay / multi-parentはapplication Serviceではなくtransport module behaviorである。
- network roleはRuntime instanceの実行責務であり、物理nodeの製品roleではない。
- application固有語彙をCore、Fabric、Route、R7、MFDTのenumやwireへ追加しない。

### 5. public ABIとversioning

package SemVer、module API version、wire version、storage schemaは別domainとする。

- package `0.x`中の`PACKAGE_EXPERIMENTAL` moduleはpackage minorでbreaking changeを
  許し、その事実をmanifestへ記録する。
- `RELEASE_SUPPORTED`へ昇格した`v1` public type/function/status値は同一major内で破壊
  しない。変更は新type/new functionまたはmodule v2で行う。
- v1 public inputは明示的にexact-sizeまたはprefix-compatibleのどちらかをtype単位で
  固定する。暗黙に混在させない。
- static archiveは必須support surfaceとする。shared ABIを保証するreleaseはsymbol
  versioningとvisibility gateを別途満たすまで未対応とする。
- module v1/v2の同一process併存可否、symbol prefix、storage/wire互換性を各module ADRで
  明示する。

private prefixや内部layoutをpublic ABIとして採用しない。各moduleは
`ninlil_<module>_v1_*`の一意symbol prefixを使う。

現時点の`V2_NOT_ALLOCATED`は「v1/v2併存可能」を意味しない。v2は未割当であり、
同一process併存をclaimしてはならない。将来v2を追加する場合は、別component/target、
header root、symbol prefix、storage namespace/prefix、wire profileを割り当て、v1/v2
同時load、誤handle、誤store、誤wireのnegative acceptanceを持つ別Accepted ADRで
`COINSTALLABLE`へ変更する。v1 symbolやrecordをv2として再解釈しない。

public layoutはfeature macroで変えない。各ABI acceptanceは同じheaderを
`macro undefined`、`all optional macros=0`、`all optional macros=1`でC11/C++ compileし、
`sizeof`、`_Alignof/alignof`、全public field offset、export symbol manifestがdefault
goldenと一致することを検査する。さらにrunnerが一時的なconditional public fieldを
注入したnegative fixtureをcompileし、**compile失敗を観測できた場合だけ**negative
probeをPASSにする。負例を実行しないfalse greenを禁止する。exact matrixはmanifestの
`abi_layout_gate_contract`へ置く。

### 6. package/component discovery

Host packageは次を提供する。

```cmake
find_package(Ninlil CONFIG REQUIRED COMPONENTS runtime fabric_v1 wifi_posix_v1)
```

- build/installに無いrequested componentはconfigure時に明示失敗する。
- `Ninlil_<component>_FOUND`、API version、support state、platform roster、
  wire/storage profile、transitive dependencyをexportする。
- tests-OFF installでも同じmetadataとconsumer behaviorを検証する。
- `compatibility-matrix.json`、dependency inventory、NOTICE、SBOMへmodule単位で記録する。
- POSIX targetはESP source/header dependencyを持たない。

ESP-IDF componentはHost CMake installとは別の正式package contractを持つ。
Kconfig、required ESP-IDF version、component dependency、public include、final ELF
map/call-path gateを固定する。Host packageのavailabilityからESP supportを推論しない。

`COMPONENTS`はCMakeの`Ninlil_FIND_REQUIRED_<component>`に従う。
required requested componentが無い、dependencyが無い、またはcurrent platform不一致なら
そのcomponentと`Ninlil_FOUND`をfalseにし、`find_package(... REQUIRED ...)`を失敗させる。
`OPTIONAL_COMPONENTS`の同じ失敗はcomponentだけをfalseにし、package全体を失敗させない。
未requested componentはtargetを作らず`FOUND=false`をexportする。

各componentは次のexact metadataをexportする。

```text
Ninlil_<component>_FOUND
Ninlil_<component>_API_VERSION
Ninlil_<component>_MODULE_API_STATE
Ninlil_<component>_COMPLETION_STATE
Ninlil_<component>_COMPLETION_STATE_BY_PLATFORM
Ninlil_<component>_PLATFORMS
Ninlil_<component>_WIRE_PROFILES
Ninlil_<component>_STORAGE_SCHEMAS
Ninlil_<component>_DEPENDENCIES
```

`COMPLETION_STATE_BY_PLATFORM`は宣言順の
`<platform>=min(platform state, そのplatformへmappedされたfeature state...)`一覧、
`COMPLETION_STATE`はその一覧のminimumである。これによりWi-Fi commonのPOSIX
featureとESP featureを単一の曖昧なtarget stateへ丸めない。Host CMakeで
`ESP_IDF_COMPONENT`だけのcomponentをrequestした場合はplatform mismatchとしてfalseにし、
ESP componentのavailabilityをHost targetから推論しない。

### 7. Radio Fragmentationの責務とRF mapping

`Ninlil::radio_frag_v1`は純粋なbounded fragmentation/reassembly moduleとする。
crypto、permit、regulatory authority、physical radio、N6/R2/R1 orchestrationは
caller-supplied versioned portであり、fragmentation engine内部layoutには含めない。
profileで必要な配列数が変わる場合もpublic struct layoutを変えず、opaque workspaceと
`workspace_required(profile_id)`を使う。

compact RFのcanonical pathは未確定である。ADR-0017が要求する
NFL1↔R7 FRAG↔NRW1 exact mapping、全message kindのlossless/unsupported規則、KATを
独立ADRでAcceptedにするまで、公開radio adapterはNFL1送受信を禁止する。

したがって、次の記述は目標compositionであり現時点の正規経路claimではない。

```text
Foundation envelope -> NFL1 -> accepted RF mapping -> R7 FRAG -> NRW1
```

### 8. Wi-FiとMFDT composition

MFDTのNCL1 bytesはADR-0021のexact Foundation owner-plane envelopeへ写像し、
Fabricのcanonical NFL1 codecと実packet-linkを通す。test専用wire tagはrelease
evidenceに使わない。

Wi-Fi目標経路:

```text
Foundation envelope -> NFL1 -> NWB1 -> TLS/TCP
```

- Wi-Fi link descriptorは`NINLIL_FABRIC_CAP_CUSTODY`を広告しない。
- MFDT end-to-end custodyとpacket-link custodyを混同しない。
- path selectionはpacket size、deadline、security、peer capability、energy、
  compliance permitを検査し、適格経路がなければ明示拒否する。
- socket/TLS成功をApplication Receipt、MFDT terminal completion、custodyにしない。

### 9. module昇格gate

public moduleへ昇格するtrancheは、同じimmutable commitで最低限次を満たす。

1. tests-OFF installと外部clean-room consumer compile/link/run。
2. C11/C++ public header self-containment、`src/` include 0、ABI/symbol manifest。
3. requested componentの存在/不在/platform mismatchを明示的に検査。
4. module単体と全module同時構成のDebug/Release、GCC/Clang、ASan/UBSan。
5. 2 module instance / 2 Runtime instanceを同一processで同時実行する。
6. default Core archiveへのoptional symbol混入0。
7. public package metadata、license、NOTICE、SBOM、source archive clean-room。

module別の追加gate:

- Fabric: 2 instance、複数link、canonical NFL1 KAT、RRMP symbol依存0。
- Wi-Fi: localhost実TLS/NFL1、切断再接続、2 adapter instance、ESP final ELF path。
- Route/Relay: 2 owner + 2 Fabric、global current owner 0、failover/restart simulation。
- R7 FRAG: profile-safe 2 engine、reorder/duplicate/loss/conflict/reassembly、Accepted RF mapping。
- MFDT: 4 KiB/32 KiB、restart/resume/replay、複数transfer manager、actual Fabric+Wi-Fi carrier。
- Final composition: 1 processで複数Application Service、relay、Wi-Fi、R7、MFDTを
  同時にlive call pathへ通す。

PASS/FAIL evidenceは任意のlogや空fileではなく
`ninlil_public_module_acceptance_evidence_v1` strict JSONとする。artifactは
acceptance/test/runner ID、対象platform、result、tested commit/tree、root-confined
non-symlink CMake build、active CTest entryのexact command/working directory、exit receipt、
stdout/stderr path/size/SHA-256、
UTC開始/終了を持つ。gateはconfigured CTest JSONからexact-once/non-disabled registrationと
実commandを検査する。tested parentからadministrative childまで以外の差分とdirty worktreeを
拒否し、CMake buildを成功させてからexact argvを再実行し、観測exit/stdout/stderrを
receiptと比較する。
自己申告exit、架空CI execution ID、`echo ctest`、comment/`if(FALSE)`内だけのregistration、
unreplayable script、path traversal/symlink escapeは証拠にしない。CI/HIL receiptをofflineで
検証するauthorityはv1に無いため、それらは`NOT_RUN`のままfail closedとする。exact contractは
`public-module-manifest.json#/acceptance_evidence_contract`を正本とする。

`platform_id`は自由な表示ラベルではない。同contractの
`platform_profile_matrix`から選ぶprofile ID、OS、architecture、toolchain family、build type、
sanitizer profile、toolchain/compiler識別子、CMake cache digestをreceiptへ同時に記録し、
profileと一致しなければ拒否する。ESP profileはさらにtarget、ESP-IDF version、final ELFと
mapのroot-confined path/sha256を必須とする。Host CTestの結果をESPへラベル替えすることは
できない。acceptanceの`PASS`/`FAIL`は、対象moduleが宣言した全platformに対応する
matrix全profileの個別receiptがcanonical順でexactに揃った場合だけ成立する。旧single
`path`/`sha256`、一部profile、重複profileは集約結果にならない。target evidenceはCMake File
API codemodelで、active CTest executableが、宣言された
acceptance sourceを実際にsource listへ持つtargetのartifactであることまで検査する。
unrelated always-pass executable、同名test registration、sourceを持たないscript targetは
receiptにならない。

本gate自身の`check`と`self-test`はCMakeへ実`add_test`し、LinuxとmacOS CIが
`ctest --show-only=json-v1`でexact commandを確認後、focused CTestとfull CTestの両方で
実行する。CMake/CI本文に文字列があるだけでは実行証拠にしない。

独立GO reviewはreviewerのGitHub node ID+login、reviewed commit、P0/P1/P2、
implementer identity roster、separation verdictに加え、GitHub PR review API receiptと
OIDC attestation provenanceをclosed JSONで要求する。reviewer名や「別人」とする自己申告は
GOにならない。v1 gateにはOIDC bundleのoffline verifierをまだ割り当てていないため、
`GO`はfail closed、全module reviewは`NOT_RUN`を維持する。exact contractは
`public-module-manifest.json#/independent_review_contract`を正本とする。

実AP、USB、SX1262、relay/failover、power-cut、soakは機材artifactが無い限り
`NOT_RUN`のままにする。Host simulation、ESP compile/link/mapは物理HILの代替ではない。

## Consequences

- OSS利用者はprivate source pathをincludeせず、必要なmoduleだけを選べる。
- 小さなendpointはPortable Coreだけをlinkできる。
- 同一nodeの複合Serviceとtransport behaviorを単一roleへ固定しない。
- process-global candidateをpublic wrapperで隠すだけでは不十分で、instance化が必要になる。
- RF mappingを仕様化するまでradio public transport昇格は待つ。
- private候補のtest合格だけではpublic/package/release完成と呼ばない。

## Acceptance of this ADR

本ADRをAcceptedへ進めるには、少なくとも次を独立再レビューで閉じる。

1. module state、package、SemVer、platform、instance ownershipが矛盾なく固定されている。
2. Fabric→RRMPの依存逆転を解消するpublic port案が実装可能である。
3. POSIX/ESP surface分離とR7責務境界が実装可能である。
4. RF mappingを別Accepted ADRへ依存することが明示されている。
5. 各moduleの公開trancheとnegative acceptanceが追跡可能である。

## Non-claims

- 本文書だけでは各moduleのpublic ABI、production support、physical HIL、法規適合を
  claimしない。
- 本文書のAcceptedは各moduleの`PUBLIC_API_SPEC_ACCEPTED`を意味しない。
- Wi-Fi socket/TLS成功をdurable custodyとしない。
- R7 reassembly成功をapplication apply/receiptとしない。
- ESP compile/linkをtarget executionとしない。
