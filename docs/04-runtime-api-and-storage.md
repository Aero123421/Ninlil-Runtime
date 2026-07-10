# 04. Runtime API and Storage

状態: Normative Foundation baseline (Fable review reflected)<br>
対象: Foundation M1a Release

## 目的

Ninlilのpublic C API、ownership、threading、state transition、永続化境界を固定します。本章に記載したFoundation APIは実装対象です。wire encoding、radio MAC、relay algorithmは本章の対象外です。

## Foundationの実行モデル

Foundation Runtimeはsingle-owner event loopです。

- Runtimeを作成したthreadだけがmutating APIを呼べます。
- Runtime自身はthreadを生成しません。
- callerは`ninlil_runtime_step()`を繰り返し呼びます。
- callbackは`ninlil_runtime_step()`の中だけで実行されます。
- callback中にmutating APIを再入してはなりません。12章で明示したread-only query/list/capacity/metricsだけを呼べます。Callbackへborrowされたevent/payload/evidenceをapplication自身のbufferへcopyすることは可能ですが、`event copy`というNinlil public APIはありません。
- 別thread/ISRからの入力はplatform portのbounded ingress queueへcopyし、owner threadが取り込みます。

将来のasync wrapperは、このsingle-owner modelの上に実装します。公開C ABIへ特定RTOSのtask modelを持ち込みません。

## Runtime Role

Runtime作成時にroleを1つ固定します。

| Role | 責務 |
| --- | --- |
| `CONTROLLER` | service registry、admission、transaction journal、receipt aggregation |
| `CELL_AGENT` | local schedule、transport custody、compliance permit、bearer observation |
| `ENDPOINT` | origin spool、inbox、dedup、application dispatch、outcome cache |

Foundation M1aが実装必須とするroleは`CONTROLLER`と`ENDPOINT`です。`CELL_AGENT`はport interfaceとtypeだけを予約し、実装はM3です。SimulatorはRuntime roleではなく、複数Runtimeをvirtual clockとfault portで駆動する外部harnessです。

## Public type原則

すべての公開structは先頭に次を持ちます。

```c
uint16_t abi_version;
uint16_t struct_size;
```

規則:

- callerはheaderが定義する`NINLIL_ABI_VERSION`と`sizeof(type)`を設定します。
- libraryは`struct_size`を超えて読み書きしません。
- opaque handle以外のpublic C++ class ABIを提供しません。
- public APIはexception、RTTI、global allocatorを要求しません。
- IDはbyte順を規定した16-byte value typeとし、pointer addressやplatform integerへ依存しません。

Opaque handles:

```c
typedef struct ninlil_runtime ninlil_runtime_t;
typedef struct ninlil_service ninlil_service_t;
```

Deferred application完了には、opaque pointerではなくcopyableな`ninlil_delivery_token_t` valueを使用します。これによりtimeout後の古いpointer参照や、handleを永久保持するための容量枯渇を避けます。

公開enumの整数値、全struct field、nullability、callback、provider vtableは[12-foundation-abi.md](12-foundation-abi.md)を正本とします。本章の概念signatureと矛盾する場合、M1aでは12章を優先します。

## Errorの5層分離

異なる意味の失敗を1つの`status`へ混ぜてはいけません。

| 層 | 型 | 例 |
| --- | --- | --- |
| API invocation | `ninlil_status_t` | invalid argument、storage I/O、wrong thread |
| Submission | `ninlil_submission_result_t` | admitted、counter-offer、rejected、idempotency conflict |
| Delivery disposition | `ninlil_disposition_t` | invalid payload、retry later、stale generation |
| Transaction | `ninlil_outcome_t` | satisfied、expired、failed definitive、unknown |
| Transport | Observation record / metrics（M1aではinternal） | carrier busy、TX failure、parent changed |

Retry guidanceはbooleanにしません。

- `RETRY_SAME_AFTER`: 同じsubmissionを指定された相対`retry_delay_ms`の経過後に再提出できる。M1aはcallerへabsolute retry timestampを返さない。
- `RETRY_MODIFIED`: 条件変更が必要。
- `OPERATOR_ACTION`: 人間または管理操作が必要。
- `NEVER`: 同じ条件では再試行しない。

## SubmissionとTransaction

Applicationが提出するものは`Submission`です。未admittedのSubmissionはtransaction IDを持ちません。

Submissionの必須field:

- service handle
- caller idempotency key
- schema version
- destination selectorまたはconcrete target set
- relative `effect_deadline_ms`
- `evidence_grace_ms`
- required evidence
- family固有metadata
- bounded payloadとcontent digest

Admission Authorityはatomic admission時に128-bit transaction IDを生成します。

### Idempotency

Idempotency keyのscopeは`source application instance + service identity(namespace + service ID)`です。Descriptor revisionをscopeへ含めません。

- 同じkeyと同じcanonical submission digestは、既存transactionを`ALREADY_ADMITTED`として返します。
- 同じkeyでdigestが異なる場合は`IDEMPOTENCY_CONFLICT`です。
- descriptor revisionを含むcanonical submission digestが異なる再提出は`IDEMPOTENCY_CONFLICT`です。Revision更新を跨いで新transactionを黙って作りません。
- key mappingは、少なくともtransaction retention終了まで保持します。
- callerがkeyを再利用して別の操作を作ることは禁止します。

## Admission AuthorityとCustody

ServiceDescriptorはadmission authorityを1つ持ちます。

- `CONTROLLER_ONLY`: downlink commandなど。controllerだけがadmitする。
- `ORIGIN_WITH_GRANT`: offline中にも生じるEventFactなど。有効なTraffic Grantを持つendpointがlocal admissionできる。

`ADMITTED`が保証するもの:

1. Admission Authorityがsubmissionとconcrete target rosterをdurable storageへcommitした。
2. authorityが所有するlocal journal bytes、queue entry、retry budget、必要なlocal dedup/outcome slotを予約した。
3. Runtimeがterminal Outcomeを生成する責任を引き受けた。

`ADMITTED`は、RF成功、LBT成功、遠隔nodeの生存、期限内のapplication effectを保証しません。

Foundation single-path profileでは、配送責任としてのCustodyを常に1つのRuntimeが所有します。M9のreceive diversityではbyte複製とlogical custodyを分けるRFCで拡張します。custody transferは次の順序です。

1. receiverがpayloadとtransaction metadataをdurable commitする。
2. receiverが`TRANSPORT_CUSTODY_ACCEPTED`を返す。
3. senderがtransfer evidenceをdurable commitする。
4. serviceの`custody_release_policy`が許す場合だけsenderがpayloadを削除する。

Transport custodyはApplication Receiptではありません。

## Submission result

```text
ADMITTED_READY
ADMITTED_SCHEDULED
ALREADY_ADMITTED
COUNTER_OFFERED
REJECTED
IDEMPOTENCY_CONFLICT
```

`ADMITTED_READY`はschedulerへ投入可能という意味であり、即時TXを意味しません。旧称`ADMITTED_NOW`は使用しません。

M1aが生成する値は`ADMITTED_READY`、`ALREADY_ADMITTED`、`REJECTED`、`IDEMPOTENCY_CONFLICT`だけです。`ADMITTED_SCHEDULED`と`COUNTER_OFFERED`は予約値で、M1aは生成しません。`ninlil_offer_accept()`はM1aでは`NINLIL_E_UNSUPPORTED`を返します。

Counter-offerは次を持ちます。

- offer ID
- original submission digest
- proposed deadline / evidence / bearer / target条件
- expiry
- reason

Counter-offer中はNinlilがsubmissionを所有せず、execution resourceも予約しません。callerは`ninlil_offer_accept()`で明示的に受諾します。受諾時に再検査し、容量が失われていればrejectできます。

## Target rosterとgroup completion

Admission時にselectorをconcrete rosterへ固定します。各target recordは最低限、次を持ちます。

- stable device identity
- logical installation identity（使用時）
- binding epoch
- site domain ID
- membership epoch
- required evidence

M1aはconcrete targetをちょうど1件だけ受理します。SelectorはM1a ABIに存在せず、将来tailとして提示されてもunsupportedです。Target countが0または2以上なら`REJECTED / NINLIL_REASON_TARGET_COUNT_UNSUPPORTED`です。

M1bで最初に追加するgroup completion policyは`ALL_TARGETS`だけです。

- 全targetがrequired evidenceへ到達した場合だけtransactionを`SATISFIED`にします。
- targetごとのoutcomeを保持します。
- 0 targetかつevidence必須のsubmissionはrejectします。
- 機器交換後のdeviceへ、既存transactionを暗黙転送しません。

`ANY_TARGET`、quorum、best-effort broadcastは将来RFCです。

## ReceiptとDelivery Disposition

Receiptはpositive evidenceだけを表します。

```text
RECEIVED < DURABLY_RECORDED < APPLIED < VERIFIED
```

- stageは累積的で、後退しません。
- Coreはenvelope、identity、digest、schema identityを検査します。
- payload validationは登録済みService Adapterが行います。
- `RECEIVED`は再構成とAdapter validationの成功後だけ生成できます。
- Persistent cacheの既知positive evidenceをreconcileまたはduplicate deliveryで再提示する場合は、transaction、target、digest、generationが一致し、cached stageがrequired evidence以上のときだけ同等のpositive evidenceになります。M1aに`ALREADY_APPLIED`という独立public enum/resultはありません。

失敗や再試行要求はDelivery Dispositionとして返します。

```text
RETRY_LATER
INVALID_PAYLOAD
UNSUPPORTED_SCHEMA
UNAUTHORIZED_SERVICE
STALE_NOT_APPLIED
APPLICATION_BUSY
APPLY_FAILED
VERIFY_FAILED
CAPACITY_EXHAUSTED
OUTCOME_UNKNOWN
```

Dispositionは、到達していないReceipt stageを成立させません。Effect certainty、retry guidance、reasonのexact combinationは12章を正本とします。

## Outcome model

Submission resultとTransaction Outcomeを分離します。admitted transactionだけがOutcomeを持ちます。

```text
ACTIVE:
  READY | WAITING_WINDOW | DISPATCHING | AWAITING_EVIDENCE | PARKED_RETRY

TERMINAL:
  SATISFIED
  EXPIRED
  CANCELLED_BEFORE_EFFECT
  SUPERSEDED_BEFORE_DISPATCH
  FAILED_DEFINITIVE
  OUTCOME_UNKNOWN
```

terminal Outcomeは不変です。late evidenceは`latest_evidence_stage`とevidence logを更新できますが、`deadline_verdict`とterminal Outcomeを書き換えません。

Snapshotは少なくとも次の二軸を返します。

- `deadline_verdict`: `PENDING | MET | MISSED | INDETERMINATE`
- `latest_evidence_stage`: `NONE | RECEIVED | DURABLY_RECORDED | APPLIED | VERIFIED`

### Deadline

- Public APIはtrusted clockから取得するpre-commit admission reference sampleからのrelative `effect_deadline_ms`を受け取ります。Sampleとabsolute deadlineは同じFULL admission transactionへ保存し、ownershipはcommit成功後にだけ成立します。
- `EventFact`はdescriptorが許可する場合だけ`NINLIL_NO_DEADLINE`を指定できます。M1a Durable Event fixtureはこれを必須とし、required evidenceまたは監査付きdiscardまでterminal deadline Outcomeへ移しません。
- `NINLIL_NO_DEADLINE`でもattempt、airtime、step workは有限です。Retry cycle枯渇時は`PARKED_RETRY`へ移り、13章の再開eventを待ちます。
- required effectが期限内に起きたかはissuer evidenceの情報で判定します。
- controllerがevidenceを受け取るための猶予を`evidence_grace_ms`として分けます。
- endpointのtrusted clockがないprofileでは、controller到着時刻を保守的な判定根拠にします。
- restart後に経過時間を証明できず、未dispatchが証明できる場合は`EXPIRED` reason=`CLOCK_UNCERTAIN`とします。
- effectの可能性がある場合は`OUTCOME_UNKNOWN`とします。

### Cancel

`ninlil_cancel_request()`の成功はcancel完了ではありません。結果を次のいずれかで記録します。

- `FENCED_BEFORE_DISPATCH`
- `PENDING_REMOTE_FENCE`
- `TOO_LATE_EFFECT_POSSIBLE`
- `ALREADY_TERMINAL`

既に起きたapplication effectを自動で元に戻しません。

## Exactly-once境界

Ninlil transportはat-least-once dispatchを基本とします。Ninlil単独でphysical effectのexactly-onceを保証しません。

二重effectを防ぐには、serviceが次のいずれかを満たす必要があります。

1. 絶対状態commandなど、同じoperationを再適用しても安全である。
2. application effectとcompletion recordを同じatomic transactionへcommitできる。
3. applicationがNinlilのpersistent operation IDとしてtransaction IDを用いて独自dedupする。

Endpoint Runtimeはcallback前に`DELIVERY_STARTED`をdurable記録し、callback成功後にresult cacheをcommitしてから`APPLIED`を発行します。effect後・result commit前のcrashでは、serviceのapply contractに従って再試行または`OUTCOME_UNKNOWN`とします。

## Public C API: Foundation

M1aは次のfunction familyを実装します。

```text
runtime_create / runtime_destroy
service_register
submit / cancel_request
event_resume / event_discard
transaction_query / transaction_list
delivery_complete
runtime_step
capacity_snapshot / metrics_snapshot
```

`offer_accept` symbolは将来互換のため予約しますが、M1aでは常に`NINLIL_E_UNSUPPORTED`です。Exact function signature、type、output初期化は[12. Foundation M1a C ABI](12-foundation-abi.md)だけを正本とし、本章では重複宣言しません。

Foundationで実装するcontract familyは`DesiredStateCommand`と`EventFact`です。他familyの登録は`NINLIL_E_UNSUPPORTED`を返します。

## Buffer ownership

- API入力pointerはcall中だけborrowedです。
- `ninlil_submit()`がadmittedを返す前に、再実行に必要な全byteをRuntime所有storageへcopy/commitします。
- rejected/counter-offerではpayload ownershipはcallerに残ります。
- callbackへ渡すpayload pointerはcallback終了までだけ有効です。非同期applyに必要なbyteはapplicationがcopyします。
- callbackが`DEFER`を返す場合、applicationはcallback中に`ninlil_delivery_token_t`の値をcopyします。callback pointer自体を保持しません。
- tokenは`ninlil_delivery_complete()`成功または規範timeoutまでlogicalに有効です。complete/timeout後はactive deferred枠を解放し、retention中の再利用は`NINLIL_E_INVALID_STATE`、retention後は`NINLIL_E_NOT_FOUND`です。
- `ninlil_delivery_complete()`はowner threadからcallback外、すなわち`runtime_step()`呼出しの間に呼びます。callback内の再入は禁止します。
- 未完了tokenはreceiverのactive deferred枠、non-terminal delivery枠、bytesを消費します。Completion timeoutとreconcile規則は12章・13章を正本とします。
- query/list/capacityの可変長outputはcaller-provided bufferを使いますが、不足時の意味は12章のAPI別規則が正本です。Transaction queryはrequired target count、capacity snapshotはrequired entry count、transaction listは指定capacity内のpartial pageを通常成功として返し、一般的な「required bytes」規則へ統一しません。
- library内部pointerをcall終了後に公開しません。

## ServiceDescriptor revision

- namespace + service ID + descriptor revisionで一意です。
- 同じidentity/revisionの再登録はdescriptor digestだけでなく全semantic fieldとlocal application IDがexact一致する場合だけ候補になります。同じRuntime lifetimeではcallback function/user pointer値もexact一致がrequired、recreate後attachはpersist済みsemantic registryとnew valid callback shapeを照合します。詳細は12章が正本です。
- 上記exact bindingのvalid mismatchは`NINLIL_E_CONFLICT`です。
- admission済みtransactionはadmission時のdescriptor revision snapshotを使います。
- descriptor updateで既存transactionのdeadline、evidence、schema、resource reservationを変更しません。

## Storage port

Storage portの完全なC vtableとtransaction semanticsは12章・14章を正本とします。概念上、少なくとも次を提供します。

```text
open / close
begin transaction
get / put / delete
commit(durability)
rollback
iterate by stable prefix
capacity snapshot
schema version read/write
```

Durability:

- `VOLATILE`: 再起動で失ってよいobservation。
- `CHECKPOINTED`: 保守的に復元可能なmetric/ledger checkpoint。
- `FULL`: commit成功後の電断で失ってはならないtransaction、receipt、event、outcome cache。

M1aでは全Core durable mutationが`FULL`を要求し、Storage ABIにcapability queryはありません。したがって`FULL`を実現できないportはservice登録時に動的拒否されるのではなく、Foundation platform preconditionを満たさない非準拠portです。Coreは12章どおり`VOLATILE` / `CHECKPOINTED`を生成せず、serviceごとのdurability fallbackも行いません。

## 必須record

- runtime metadata / storage schema
- service descriptor snapshot
- transaction
- concrete target roster
- reservation
- idempotency mapping
- outbox item
- attempt
- receipt / late evidence
- target outcome
- endpoint inbox / event spool
- persistent result cache
- bounded observation summary

## Atomic boundary

Controller admissionは次を1 storage transactionでcommitします。

```text
transaction
+ target roster
+ descriptor snapshot reference
+ reservation
+ idempotency mapping
+ first outbox item
```

Endpoint EventFact local admissionは次を1 transactionでcommitします。

```text
event identity
+ payload/digest
+ origin transaction ID
+ grant/epoch binding
+ retry budget
+ origin spool item
```

Endpoint application resultは次をreceipt発行前にcommitします。

```text
delivery state
+ application result/result digest
+ highest positive evidence stage
+ dedup/result-cache expiry
```

## Crash recovery

起動時にRuntimeは次を行います。

1. storage schemaとmigration状態を検査する。
2. incomplete atomic transactionをstorage backend規則に従ってrollbackする。
3. admittedかつnon-terminalなtransactionとreservationを列挙する。
4. prepared attemptとsend observationを分け、observationの有無/commit-unknownをauthoritative recoveryする。
5. retry budgetとdeadlineを再評価する。
6. send observation前crashは同じtransaction/attempt/immutable messageだけをduplicate-safeに再invokeし、observation後のlogical retryだけ別attempt IDで再開する。
7. terminal Outcomeをdispatch対象へ戻さない。

M1a typed bearerはphysical frame nonceを定義しません。M5 protected wireではBearer invocationごとにfresh frame nonceを使いますが、send observation前crash replayでもlogical transaction/attempt/message bindingは維持します。Observation `COMMIT_UNKNOWN`のauthoritative解決前は再invokeしません。

## Resource accounting

ReservationはAdmission Authorityが所有するlocal resourceについて、少なくとも次を記録します。

- journal bytes
- queue entries / bytes
- target count
- retry attempts
- receipt/evidence records
- local dedup/result-cache entry。remote枠を予約済みと主張しない
- expiry

Reservationはterminal Outcomeと必要retentionの完了後にだけ解放します。storage pressure時もEventFact、terminal evidence、idempotency mappingをsilent deleteしません。削除順序は07章とFoundation profileで固定します。

## Foundation受入条件

- admission commitの各write pointでcrashしても、所有権が二重化・消失しない。
- controller restart後、admitted transactionを同じtransaction IDで再開する。
- endpoint restart後、duplicate logical transaction/business recordを作らず、application effectはapply contractに従い再適用または`OUTCOME_UNKNOWN`にする。
- eventのdurable commit前に`DURABLY_RECORDED`を返さない。
- same idempotency key + different digestを明示conflictにする。
- terminal Outcomeをlate receiptで反転しない。
- queue/storage上限時にdeterministic reasonでrejectする。
- callback再入、wrong thread、small bufferを構造化errorにする。
