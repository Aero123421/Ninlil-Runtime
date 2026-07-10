# 14. Foundation Ports and Deterministic Simulator

状態: Normative pre-alpha
対象: Foundation M1a port、fixture、conformance harness

## 目的

本章は、Foundation Coreの外側にあるstorage、bearer、clock、entropy、Tx Gate、fault hookと、複数Runtimeを駆動するdeterministic simulatorの観測可能なcontractを固定します。

目標は、別の実装者が別の言語・backendでportとharnessを実装しても、同じ入力、seed、fault scriptから同じstorage view、delivery順、public resultを得られることです。host OSのthread scheduling、filesystem使用量、C struct padding、container iteration順へ結果を依存させてはなりません。

## 正本関係

- public enumの整数値、public struct、opaque handle、nullability、vtable layoutは[12-foundation-abi.md](12-foundation-abi.md)を正本とします。本章はvtableを再宣言せず、そのobservable semanticsを定めます。
- transaction、deadline、cancel、Receipt、EventFact retry/recoveryの状態遷移は[13-foundation-state-machine.md](13-foundation-state-machine.md)を正本とします。
- 本章はport transaction、durability、capacity unit、simulator ordering、fixture byteを詳細化します。
- SimulatorはRuntime roleではありません。`CONTROLLER`と`ENDPOINT`を外部から駆動するtest harnessです。`SIMULATOR`というRuntime role、identity、admission authorityを作ってはなりません。
- M1aはconcrete target 1件だけを受理します。EventFactは`NINLIL_NO_DEADLINE`かつ`evidence_grace_ms = 0`であり、8-attempt cycle枯渇後も`PARKED_RETRY`でpayloadを保持します。fresh Bearer availability epoch + `available=1`または一意なoperator resume operationでだけ次cycleへ進みます。

本章で使用する`MUST`、`MUST NOT`、`SHOULD`、`MAY`は[README.md](README.md)の規範語に従います。

## Scopeとmilestone applicability

### M1aで実装必須

- `ninlil_storage_ops_t`のPOSIX SQLite portとconformance test double
- `ninlil_bearer_ops_t`のtyped simulated bearer
- `ninlil_clock_ops_t`のPOSIX monotonic clockとvirtual clock
- `ninlil_entropy_ops_t`のOS entropyとdeterministic TEST entropy
- `ninlil_tx_gate_ops_t`のfail-closed stubとTEST専用virtual permit
- `ninlil_origin_authorization_ops_t`のTEST専用synthetic grant evaluation
- `ninlil_execution_ops_t`によるowner-context検査
- named fault hook、fault script、crash/restart harness
- 本章のgeneric identity、capability、grant、submission、golden vector

M1aのsimulatorはpublic radio wire format、暗号session、real Join、relay、fragmentation、RF性能、法規適合を実装・証明しません。

### 後続milestoneへの適用

| Gate | 最初に必須 | M1aでの扱い |
| --- | --- | --- |
| public port ABI、storage atomicity、stable ordering、bounded accounting | M1a | 全項目必須 |
| deterministic replay、named crash、same-seed reproducibility | M1a | 全項目必須 |
| synthetic identity / grant / permit | M1a | `TEST` artifactだけ。production claim禁止 |
| ESP-IDF storage/clock/entropy/execution port | M3 | 本章のportable conformance subsetとpower-cut HILが必須 |
| real identity、membership、grant lifecycle | M4 | synthetic grantを置換。TEST外でfixture受理禁止 |
| real session security、TxPermit、radio bearer | M5 | virtual permitを置換。本章のone-shot/fail-closed境界は維持 |
| KGuard adapter | M6 | generic fixtureを置換してもCore/portへKGuard ruleを追加しない |
| Wi-Fi/USB、scheduler、50-node load | M7 | bearerごとに同じcustody/status/accounting contractを実装 |
| relay/multi-cell/multi-parent | M8〜M9 | 同じlogical transactionとattempt規則を維持し、別RFCでmetadataを追加 |

後続milestoneの要件をM1aの未達として扱いません。逆に、M1aのvirtual permit、synthetic TEST identity/origin authorization、fault test合格をM4/M5のsecurity/compliance合格として表示してはなりません。M1a fixtureはcryptographic authenticationを提供しません。

## Port共通contract

### ABIとlifetime

- vtable型、method名、引数、handle型は12章をそのまま使用します。独自のpublic extension fieldを同じABI versionへ追加してはなりません。
- `ninlil_platform_ops_t`が参照するvtable、provider context、open済みhandleは、そのRuntimeの`ninlil_runtime_destroy()`完了まで有効でなければなりません。
- 入力pointerはmethod call中だけborrowedです。非同期処理またはqueueへ残すportは、成功を返す前に必要byteをprovider所有領域へdeep-copyします。
- output pointerはcaller所有です。provider内部pointerをcall終了後まで公開してはなりません。
- Coreはclose済みhandle、commit/rollback済みtransaction、close済みiterator、release済みreceived messageをportへ渡しません。このprecondition違反をpublic APIで検出した場合は`NINLIL_E_INVALID_STATE`です。
- portはcallbackでCoreへ再入しません。completionはbounded ingressへcopyし、owner contextの`ninlil_runtime_step()`が`receive_next`等で取り込みます。

### Runtime storage namespace ownership

`ninlil_runtime_config_t.storage_namespace`はpath/textでなくopaque bytesです。Identityは`uint32 length + exact byte sequence`だけで、inclusive lengthは1〜255です。NUL termination、UTF-8、normalization、case folding、`/`や`\\`のpath意味を与えません。

Runtime createは全config validation後、Storage `open`より前にnamespaceをCore allocatorへexact deep-copyします。Create成功時はRuntime destroy完了までCoreがcopyを所有し、Storage `open`へはそのcopyをcall中borrowed viewとして渡します。Storage providerがhandle lifetimeへ必要なら自らcopyします。

| Vector | Input / fault | Required result |
| --- | --- | --- |
| `NS1_MIN` | length=1、bytes=`00` | valid。Storage openへlength 1 / exact `00` |
| `NS2_MAX` | length=255、0x00〜0xffを含むfixture bytes | valid。全255 bytes exact一致 |
| `NS3_OPAQUE` | length=5、bytes=`00 ff 2f 41 00` | valid。embedded NUL、non-UTF-8、`/`、caseを変換しない |
| `NS4_INVALID_SHAPE` | length=0/data NULL、length=0/data non-NULL、length=256、length>0/data NULL | 各`NINLIL_E_INVALID_ARGUMENT`、Runtime NULL、allocator/storage open 0 |
| `NS5_DEEP_COPY` | create call後にcaller buffer全byteをxorし解放 | Runtime/Storage namespaceはcreate時bytesのまま。Caller pointerを保存しない |
| `NS6_ALLOC_FAIL` | namespace copy allocation failure | `NINLIL_E_CAPACITY_EXHAUSTED`、Runtime NULL、Storage open 0 |
| `NS7_LATE_CREATE_FAIL` | copy/open成功後に別create stepがdefinite failure | Storage close後にCore copyをexactly 1回deallocate、Runtime NULL |
| `NS8_DESTROY` | create成功後destroy | Storage close完了後にCore copyをexactly 1回deallocate。destroy前解放0 |
| `NS9_SINGLE_ACTIVE_LEASE` | 同じexact namespaceでRuntime A live中にB create、A clean destroy後のB retry、A crash dead-owner未確認/確認後reopen | Live/未確認はStorage BUSY→`NINLIL_E_WOULD_BLOCK`/B NULL。Clean closeまたはdead-owner確認後だけB open成功。Crash pathはcloseを偽装せず、reopenがrecovery fence完了前にBearer/effectを開始しない。別namespaceは独立 |

`NS3`、ASCII `A`、ASCII `a`、末尾NUL有無、同prefixで異なるlengthはすべて別namespaceです。Pointer identityが違ってもlength/bytesが同じなら同namespaceです。Restart/reopenは同じowned bytesを使用し、query sequence、attempt collision index、capacity metadata等のdurable scopeを取り違えません。

### Runtime create lifecycle vectors

Harnessは`ninlil_runtime_create()`のobservable call traceを次の9 stageで照合します。Earlier stageが失敗したらlater stageへ到達せず、non-NULL `out_runtime` storageはrequired pointer validation直後にNULL化し、stage 9までRuntime handleをpublishしません。

| Stage | Exact work |
| ---: | --- |
| 1 | config/platform/nested ABI、reserved/enum/range/null、全required vtable/function pointerをpure validation |
| 2 | `execution.current_context_id`をexactly 1回呼び、non-zero owner contextをcapture |
| 3 | Core state/vtable/config scalar copy、namespace exact deep-copy、profile-bounded tableをAllocatorで確保 |
| 4 | copied namespaceで`storage.open(..., NINLIL_STORAGE_SCHEMA_M1A, ...)`をexactly 1回 |
| 5 | schema/profile binding、commit-unknown resolution、recovery scan/fence、persistent capacity metadataを完了 |
| 6 | `bearer.open(user, runtime_id, role, ...)`をexactly 1回。M1aはeager openで、lazy openしない |
| 7 | `clock.now`をexactly 1回取得し、trusted sampleをmetrics startへ固定。`clock_epoch_id` non-zero、`now_ms == 0` valid |
| 8 | metrics epoch IDを最大4 entropy-call/partial/all-zero規則で取得。Collision checkなし。transaction/attempt用entropyは未消費 |
| 9 | Stage 5で再構成したdurable causesをfixed priorityへproject（cleanならhealth OK/reason NONE、markerありならDEGRADED/exact reason）、zero metrics、start sample/epoch ID、owner/handlesをfinalizeし、Runtimeをexactly 1回publish |

| Vector | Fault / setup | Required result and exact boundary |
| --- | --- | --- |
| `CR1_SUCCESS_ORDER` | Foundation Controller/Endpoint fixtureをclean namespaceでcreate | stage 1→9のexact trace、`NINLIL_OK`、non-NULL Runtime。Storage recovery完了前のBearer open、Bearer open前のclock/entropyは0 |
| `CR2_PURE_VALIDATION` | stage 1の各null/header/reserved/enum/range/profile violationを1つずつ注入し、outをpoison | exact API status、out NULL、Allocator/Execution/Storage/Bearer/Clock/Entropy call 0 |
| `CR3_OWNER_CONTEXT_ZERO` | current context ID=0 | `NINLIL_E_DEGRADED`、out NULL、context call 1、Allocatorと他Port call 0 |
| `CR4_ALLOC_PREFIX_ROLLBACK` | stage 3の各allocation pointを1つずつNULLにする | `NINLIL_E_CAPACITY_EXHAUSTED`、out NULL、取得済みallocationをreverse orderでexactly once free、Storage open 0 |
| `CR5_STORAGE_OPEN_MAPPING` | openからBUSY / NO_SPACE / IO_ERROR / CORRUPT / unexpected NOT_FOUND / BUFFER_TOO_SMALL / UNSUPPORTED_SCHEMA / COMMIT_UNKNOWNを返す | 順に`WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_CORRUPT / STORAGE_CORRUPT / UNSUPPORTED / STORAGE_COMMIT_UNKNOWN`。返却handleがあればclose後、reverse free |
| `CR6_RECOVERY_BEFORE_BEARER` | clean initial binding、exact reopen、schema/role/environment/runtime ID/19 limits/3 retentions各1-field mutation、current identity exact/forward/stale/device mismatch、initial/rotation commit-unknown、各Storage failure | Cleanはbinding+capacity+transaction/ordered-input/owner counters+visited cursor+identityを1 FULL commit、exact identityはwrite0、higher binding/membership epochだけcurrent identityをFULL更新。Immutable mismatch=`UNSUPPORTED`、device/stale identity=`CONFLICT`、partial/mismatched counter=`STORAGE_CORRUPT`、Bearer/clock/entropy 0。Specific namespace/identity hooks、unknown all-present/all-absentまたはrotation applied/not-appliedへ収束 |
| `CR7_BEARER_OPEN_MAPPING` | openからOK+NULL、WOULD_BLOCK、UNAVAILABLE、DENIED、EMPTY、LOST_UNKNOWN、CORRUPT | statusは順に`DEGRADED / WOULD_BLOCK / WOULD_BLOCK / UNSUPPORTED / DEGRADED / DEGRADED / DEGRADED`。Bearer handleがあればclose→Storage close→reverse free |
| `CR8_CLOCK_SAMPLE` | stage 7でvalid trusted epoch + `now_ms=0`、temporary、UNCERTAIN、permanent、trusted+全zero epoch、invalid trust enum、recovered stateに対するregressionを個別実行 | time 0はcreate継続。temporary/UNCERTAINは`NINLIL_E_CLOCK_UNCERTAIN`、他は`NINLIL_E_DEGRADED`。failureはclock call 1、entropy 0、reverse cleanup |
| `CR9_METRICS_ENTROPY` | candidate partial/failure/all-zeroを0〜3回後にvalid non-zero、または4回全てinvalid/failure。直前createと同じnon-zero candidateのvariantも実行 | validならそのcandidateをmetrics epochへ使用。同値variantもcollision rejectしない。4回失敗は`NINLIL_E_ENTROPY`、transaction/attempt draw 0、reverse cleanup |
| `CR10_PUBLISH_AND_METRICS` | stage 8後/9前のhookでhandle visibilityを観測。Cleanとdurable RECOVERY_REQUIRED/counter markerありを各実行 | publish前はout NULL。Success時だけmetrics epoch/start epoch non-zero、全metrics zero。Clean health=OK/NONE、markerありは固定priorityDEGRADED/exact reason |
| `CR11_FIRST_FAILURE_WINS` | earlier stage failure、later stage fault、cleanup監視を同時script | exact sequenceで最初に観測したfailureだけを返し、later fault occurrence 0。Cleanupはoriginal statusを上書きせず、Port `user`をfreeしない |

Stage 4以降の失敗cleanupは、存在するresourceだけを`bearer.close` → live Storage transaction/iterator 0確認 → `storage.close` → service/table/namespace/runtime allocationのreverse deallocate順で処理します。同じresourceを二重close/freeせず、Origin AuthorizationとTx Gateをcreate中に呼びません。

### Runtime destroy lifecycle vectors

`ninlil_runtime_destroy()`はprecondition validationとconsume boundaryを分離します。Validation成功後にin-memory `DESTROYING`へ入ったpointが不可逆なconsume boundaryで、それ以降はreturn statusにかかわらずRuntime、Service、Token handleがinvalidです。

| Vector | Setup / fault | Required result |
| --- | --- | --- |
| `DR1_PRECONDITION_NO_CONSUME` | Runtime NULL、wrong owner context、callback/re-entry中を個別実行 | 順に`NINLIL_E_INVALID_ARGUMENT / NINLIL_E_WRONG_THREAD / NINLIL_E_REENTRANT`。Runtime/Service/Port state不変、valid handleは未consumeで、正しいcontextから後続destroy可能 |
| `DR2_NO_ACTIVE_TOKEN` | active token 0、pending non-token transaction/outboxあり | DESTROYING後もStorage writeとdestroy hookは0。Bearer close→Storage close→reverse free、`NINLIL_OK`。Pending journalをterminal/no-effectへ変更しない |
| `DR3_ACTIVE_GROUP_OK` | 3 active tokensをcontext ID byte順/generation順と逆に作成 | unsigned-byte lexicographic context ID、次にgeneration昇順へ列挙し、全token invalidation、active slot release、全Delivery RECOVERY_REQUIREDを**1 transaction / 1 FULL commit**。before/after hook各1、partial group visibility 0、`NINLIL_OK` |
| `DR4_DEFINITE_GROUP_FAILURE` | group begin/write/commitへBUSY、NO_SPACE、definite IO/commit failure、CORRUPT/schema invariantを個別注入 | 順に`WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT`。Atomic token mutation 0、after hook 0、cleanup続行、全public handle consumed |
| `DR5_COMMIT_UNKNOWN_BOTH_TRUTHS` | group commitでhidden committed / not-committedを各実行し、PortはCOMMIT_UNKNOWN | 両方`NINLIL_E_STORAGE_COMMIT_UNKNOWN`、after hook 0、cleanup続行、handle consumed。次createがauthoritative journalを解決し、previous instanceの全active markerをcallback 0でRECOVERY_REQUIREDへ収束 |
| `DR6_BEFORE_AFTER_CRASH` | `runtime.before_destroy_recovery_commit`と`runtime.after_destroy_recovery_commit`で各crash | before crash recoveryはgroup全非commit、after crash recoveryはgroup全commitで、部分token state 0。Crash pathはgraceful close/freeを偽装せず、次create recovery fence後に旧tokenをactiveへ戻さない |
| `DR7_CLEANUP_ORDER` | token group OK/failure/unknownの各caseで全resourceをtrace | group結果観測後にBearer close→live Storage transaction/iterator 0確認→Storage close→service/table/namespace/runtime allocationをreverse exactly-once free。Port `user`はfreeしない |
| `DR8_DESTROYING_SIDE_EFFECT_FENCE` | consume boundary直後にpending callback/send/query/wakeを用意 | callback、Bearer send、positive Receipt/Disposition、public queryを追加実行せず、scheduled wakeはdead generationとしてno-op |

`DR3`〜`DR8`ではdestroy return直後のdangling handleを再callしません。Durable stateは新Runtimeを同じnamespaceでcreateして照合します。Definite failureはjournal/DELIVERY_STARTEDを削除せず、COMMIT_UNKNOWNはall-or-noneのどちらも「no effect」と推測しません。Cleanup operationはprimary destroy statusを上書きしません。

### Owner contextとblocking

- Foundation Runtimeを変更するport methodは、12章の`ninlil_execution_ops_t.current_context_id`で作成時ownerと同じcontextからだけ呼びます。
- ISR、signal handler、別threadからRuntime stateを直接変更してはなりません。
- M1aのport callはboundedです。待ち続ける代わりにStorageは`NINLIL_STORAGE_BUSY`、Bearerは`NINLIL_BEARER_WOULD_BLOCK`、Clock/Entropyは`NINLIL_PORT_TEMPORARY_FAILURE`を返します。
- Coreは各temporary statusを必要に応じて`NINLIL_E_WOULD_BLOCK`または13章のordered transport/storage inputへ変換し、bounded retry/not-beforeを使用します。
- providerが自らthreadを作る場合も、そのschedule順をCoreの意味論へ露出させてはなりません。simulator providerはthreadを作ってはなりません。

### Port statusとAPI statusの分離

Port vtableは`ninlil_status_t`を返しません。Storage、Bearer、Clock/Entropy、Tx Gateは12章の専用statusを返し、CoreがAPI status、Observation、Submission reasonへ写像します。

Storageの規範mapping:

| Storage status | Core/API mapping |
| --- | --- |
| `NINLIL_STORAGE_OK` | operationの規範postcondition成立 |
| `NINLIL_STORAGE_NOT_FOUND` | internal absence branch。public queryなら`NINLIL_E_NOT_FOUND` |
| `NINLIL_STORAGE_BUFFER_TOO_SMALL` | `NINLIL_E_BUFFER_TOO_SMALL`、required lengthを保持 |
| `NINLIL_STORAGE_NO_SPACE` | admissionならSubmission reason=`CAPACITY_EXHAUSTED`、API operationなら`NINLIL_E_CAPACITY_EXHAUSTED` |
| `NINLIL_STORAGE_IO_ERROR` | definite non-commitなら`NINLIL_E_STORAGE` |
| `NINLIL_STORAGE_CORRUPT` | `NINLIL_E_STORAGE_CORRUPT`、Runtimeをfail-closed degradedへ移す |
| `NINLIL_STORAGE_COMMIT_UNKNOWN` | `NINLIL_E_STORAGE_COMMIT_UNKNOWN`、reopen/reconcile必須 |
| `NINLIL_STORAGE_BUSY` | `NINLIL_E_WOULD_BLOCK`。operation未受理 |
| `NINLIL_STORAGE_UNSUPPORTED_SCHEMA` | create/openを`NINLIL_E_UNSUPPORTED`で停止。旧schemaへfallbackしない |

Bearer statusはAPI invocation errorと混ぜず、13章のtransport inputへ写像します。

| Bearer status | Meaning / reducer input |
| --- | --- |
| `NINLIL_BEARER_OK` | send/receive/state operation成功。sendは`out_result.kind`も検査 |
| `NINLIL_BEARER_EMPTY` | 現在受信messageなし。error/Observationを生成しない |
| `NINLIL_BEARER_WOULD_BLOCK` | 一時的capacity/busy。message ownershipは移らない |
| `NINLIL_BEARER_UNAVAILABLE` | 接続機会なし。message ownershipは移らない |
| `NINLIL_BEARER_DENIED` | permit/policy denial。success、sent、Receiptにしない |
| `NINLIL_BEARER_LOST_UNKNOWN` | send/delivery成否不明。attemptを`delivery possible`として扱う |
| `NINLIL_BEARER_CORRUPT` | invalid ingress/port state。positive evidenceを生成しない |

Clock/Entropyの`NINLIL_PORT_OK`、`NINLIL_PORT_TEMPORARY_FAILURE`、`NINLIL_PORT_PERMANENT_FAILURE`は用途別に扱います。Clock failureまたはuncertain sampleは`NINLIL_E_CLOCK_UNCERTAIN`、Entropy failureは`NINLIL_E_ENTROPY`です。permanent failureで安全に継続できないRuntimeは`NINLIL_E_DEGRADED`へ移します。Tx Gateの`DENIED`/`TEMPORARY`はBearer sendを呼ばず、policy denialまたはbounded retry inputにします。

Origin Authorizationは5層error分離を維持します。`NINLIL_ORIGIN_AUTH_OK + allowed=0`だけが`NINLIL_OK + Submission REJECTED`です。`NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE`はAPI `NINLIL_E_WOULD_BLOCK`でhealth causeを追加せず、`PERMANENT_FAILURE`またはinvalid/partial decisionはAPI `NINLIL_E_DEGRADED`かつRuntime health reason `NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE`です。後者もSubmission resultはINVALID/reason NONEで、policy rejectionへ偽装しません。全caseでEventFact ownershipやspoolを作りません。

OS error、SQLite result、FreeRTOS errorをpublic/port statusへそのままcastしてはなりません。diagnostic detailはsecret/payloadを含まないbounded provider codeとして別に保持します。

## Storage port contract

### Capabilityとopen

`ninlil_storage_ops_t`の`open`、`close`、`begin`、`get`、`put`、`erase`、`iter_open`、`iter_next`、`iter_close`、`capacity`、`commit`、`rollback`を使用します。handle型とsignatureは12章を正本とします。

- 1つのRuntimeは同じstore identityをexclusive writerとしてopenします。競合はprovider内部でboundedに解決できなければ`NINLIL_STORAGE_BUSY`です。
- `open`成功前または`close`後にtransactionを開始してはなりません。
- clean `close`時にlive transaction/iteratorがあってはなりません。Coreはiteratorをcloseし、active transactionをrollbackしてからstorageをcloseします。`close`は暗黙commitしません。crash時は`close`を呼ばずbackend recovery規則へ委ねます。
- Storage ABIにcapability declaration/queryはありません。M1aへ渡すproviderは`FULL`の下記semanticsを実装するplatform preconditionで、Coreはこれをservice registration時にdynamic判定しません。`VOLATILE` / `CHECKPOINTED`はforward ABI valueで、M1a Coreは生成しません。このpreconditionを満たさないproviderはM1a非準拠です。

### Transaction lifecycle

Storage transactionの状態は次だけです。

```text
NEW --begin/OK--> ACTIVE
ACTIVE --commit/OK--> COMMITTED_CLOSED
ACTIVE --commit/definite error--> ABORTED_CLOSED
ACTIVE --commit/COMMIT_UNKNOWN--> UNKNOWN_CLOSED
ACTIVE --rollback/OK--> ROLLED_BACK_CLOSED
ACTIVE --rollback/error--> ABORTED_DEGRADED_CLOSED
```

規則:

- 1 storage handleにつきactive write transactionは最大1つです。nested transactionとimplicit savepointは禁止します。
- `begin`成功時に、以後のread viewとなるsnapshotを固定します。
- `get`、`put`、`erase`、iteratorは`ACTIVE`でだけ有効です。
- transactionはread-your-writesです。`put`した値を同じtransactionの`get`と新規iteratorから読め、`erase`したkeyは見えません。
- 同じkeyへの複数`put`は最後の値、`put`後の`erase`は不存在、`erase`後の`put`は最後の値になります。
- 存在しないkeyの`erase`はidempotentな`NINLIL_STORAGE_OK`です。
- `commit`は戻り値にかかわらずtransaction handleをconsumeします。callerは同じtransactionへ再commit、rollback、read/writeしてはなりません。
- `rollback`はtransaction handleを常にconsumeします。`NINLIL_STORAGE_OK`だけがstaged mutationを一切公開しないpostconditionを保証します。error時はhandleを再利用せずRuntimeをdegradedにしてstorageをreopenします。
- definite commit errorはatomic groupが非commitであることをproviderが保証する場合だけ`NINLIL_STORAGE_IO_ERROR`等を返せます。保証できなければ`NINLIL_STORAGE_COMMIT_UNKNOWN`です。
- commit後のcleanup、checkpoint、log truncation失敗で、既にdurableなcommitをfailureとして返してはなりません。`NINLIL_STORAGE_OK`を返し、cleanup問題をbounded diagnosticへ記録します。

### Key、value、prefix iteration

- keyは1〜255 bytesのopaque byte stringです。NUL、非UTF-8、`0xff`を含められます。
- valueは0 bytesを許可し、single value上限はinclusive `NINLIL_M1A_MAX_STORAGE_VALUE_BYTES = 65,536`です。これを超えるvalueはmutation前に`NINLIL_STORAGE_NO_SPACE`、Coreが超過valueを発行した場合はCore contract failureです。Total entry/byte limitはcapacity値で別に検査します。
- providerはcall終了前にkey/valueをcopyします。caller bufferのaddressやlifetimeを保存しません。
- key比較は各byteをunsigned 0〜255として行うlexicographic orderです。共通prefixが同じ場合は短いkeyが先です。locale、Unicode、hostのsigned `char`に依存してはなりません。
- prefixは0〜255 bytesです。0-byte prefixは全keyを表します。
- `iter_open`は呼出し時点のtransaction viewを固定します。その後同じtransactionへ行った`put`/`erase`は、既にopenしたiteratorへ反映せず、新しいiteratorへ反映します。
- `iter_next`はprefixに一致するkeyを上記orderで各1回だけ返します。終端は`NINLIL_STORAGE_NOT_FOUND`であり、errorではありません。
- output buffer不足時は`NINLIL_STORAGE_BUFFER_TOO_SMALL`と必要key/value bytesを返し、iterator位置を進めません。
- iterator open中もtransactionをcommit/rollbackできますが、その時点ですべてのiteratorは無効になります。

### Mutable output buffer vectors

`get` / `iter_next`へ渡す各`ninlil_mut_bytes_t`はcall前`length=0`です。Capacity=0ならdata NULL、capacity>0ならdata non-NULLです。Input length non-zeroまたはcapacity/data shape違反は`NINLIL_STORAGE_CORRUPT`で、length/data/iterator positionを変更しません。

| Status | Length output | Data / iterator mutation |
| --- | --- | --- |
| `NINLIL_STORAGE_OK` | exact returned count、0〜capacity | `[0,length)`だけexact write、tail unchanged。iterだけ1 row進む |
| `NINLIL_STORAGE_BUFFER_TOO_SMALL` | required count。iter pairはkey/value両方 | 全data unchanged、iterator不変 |
| `NINLIL_STORAGE_NOT_FOUND` | 0 | 全data unchanged。get missing / iter end |
| other error | 0 | 全data unchanged、iterator不変 |

| Vector | Setup | Required result |
| --- | --- | --- |
| `MB1_ZERO_VALUE` | existing zero-byte value、capacity=0/data NULL/length=0 | OK、length=0、dereference 0 |
| `MB2_GET_EXACT_AND_TAIL` | value length=3、capacity=8、buffer=`aa`×8 | OK、first3 exact、length=3、bytes3..7は`aa` |
| `MB3_GET_SMALL` | value length=5、capacity=4、sentinel buffer | BUFFER_TOO_SMALL、length=5、全4 bytes unchanged |
| `MB4_GET_MISSING` | missing key、capacity>0 sentinel | NOT_FOUND、length=0、data unchanged |
| `MB5_GET_ERROR` | BUSY/IO/CORRUPT injection | 各length=0、data unchanged。StatusをNOT_FOUNDへ丸めない |
| `MB6_INVALID_INPUT` | length=1、capacity0/data non-NULL、capacity>0/data NULLを各実行 | CORRUPT、input length/data unchanged、provider write 0 |
| `MB7_ITER_PAIR_SMALL` | next row key/value required=4/6、key capacity=3、value capacity=8 | BUFFER_TOO_SMALL、length=4/6、両data unchanged、position不変。拡張retryで同じrow |
| `MB8_ITER_SUCCESS_END` | 両capacity十分でsuccess後、次がend | successは同じrowのkey/valueを書き1 rowだけadvance。Endは両length=0、data unchanged |

`iter_next`で片方だけ先にcopyしてから他方の不足を発見してはなりません。BUFFER_TOO_SMALL/error retry、commit/rollbackによるimplicit iterator consume、明示iter_closeを組み合わせてもrow skip/duplicate write/double closeを作りません。

### Handle/capacity output vectors

| Vector | Script | Required result |
| --- | --- | --- |
| `SH1_OPEN_SHAPE` | openのOK+handle、OK+NULL、各non-OK+NULL/non-NULL、unknown status | Valid shapeだけ採用。OK+NULLとunknownはCORRUPT。Failure+handleはclose exactly1後CORRUPT、二重close/handle publish 0 |
| `SH2_BEGIN_SHAPE` | beginの同matrix | Failure+txnはrollback exactly1でconsume後CORRUPT。OK+NULLはCORRUPT、live txn/table mutation 0 |
| `SH3_ITER_OPEN_SHAPE` | iter_openの同matrix | Failure+iterはparent ACTIVE中にiter_close exactly1後CORRUPT。OK+NULLはCORRUPT、iterator leak/advance 0 |
| `SH4_CAPACITY_SHAPE` | OK valid/exact boundary、OK max0/used>max/header poison、各non-OK numeric poison、unknown | Validだけchecked availableを導出。Invalid/poison/unknownはCORRUPT、capacity admission判断0 |
| `SH5_VALUE_BOUNDARY` | put length 0、65,536、65,537 | first2はtotal capacity内ならOK、65,537はmutation 0/NO_SPACE。Host/provider固有の別上限へsilent clampしない |
| `BH1_BEARER_OPEN_SHAPE` | Bearer openのOK+handle、OK+NULL、各non-OK+NULL/non-NULL、unknown | Valid shapeだけpublish。OK+NULLはDEGRADED、failure+handle/unknownはclose exactly1後DEGRADED。Storage close→reverse free、二重close0 |

### FULL durabilityとatomicity

`FULL` transactionの`commit`が`NINLIL_STORAGE_OK`を返すのは、次がすべて成立した後だけです。

1. transaction内の全mutationが1つのatomic groupとしてbackendへ渡された。
2. crash/power-loss profile内の必要なdataとcommit metadataがdurable boundaryを越えた。
3. recovery後に全mutationが見えるか、commit前の全状態が見えるかのどちらかで、部分状態が見えない。
4. callerへsuccessを返すために必要なbackend acknowledgementを受けた。

Foundationのcontroller admission、EventFact local admission、endpoint result cache、Receipt/outcome更新は`FULL`です。POSIX reference portはSQLiteの単一transaction、WAL、`synchronous=FULL`、foreign keys有効を使用します。filesystemやhardwareがSQLiteの要求したflushを偽る範囲までは保証に含めず、port profileへ明記します。

Vector `FULL1_M1A_REQUESTS_FULL`はspy Storage PortでM1a Coreが行う全durable commitを記録し、durabilityが全て`NINLIL_DURABILITY_FULL`、`VOLATILE` / `CHECKPOINTED`生成0、capability query/register-time判定0であることを検査します。

### Commit結果不明

`NINLIL_STORAGE_COMMIT_UNKNOWN`は「失敗」や「rollback済み」ではありません。Coreはpublic operationへ`NINLIL_E_STORAGE_COMMIT_UNKNOWN`を返します。

- providerはtransaction handleを閉じ、同じbackend transactionを再試行させません。
- Runtimeは対応operation IDとidempotency keyを保持し、success、REJECTED、Receipt、payload解放を公開しません。
- storage handleを閉じて再openし、schema/recoveryを完了した後、authoritative record、idempotency mapping、atomic group markerを読み直します。
- groupが全て存在すれば、その既存transactionへ`ALREADY_ADMITTED`等で収束します。
- groupが全て不存在なら、同じidempotency keyとcanonical digestで新しいstorage transactionを開始できます。
- 部分group、digest conflict、recoveryでも判定不能なら`NINLIL_E_DEGRADED`でfail closedです。
- callerはcommit不明を受けたSubmissionについて新しいidempotency keyを生成してはなりません。

Simulatorの`storage_commit_unknown` faultは、hidden ground truthとして`committed`または`not_committed`を明示し、Storage portは常に`NINLIL_STORAGE_COMMIT_UNKNOWN`を返します。Coreのpublic mappingは`NINLIL_E_STORAGE_COMMIT_UNKNOWN`です。両方のrecovery収束をtestします。

### Capacity unitとmapping

Storage capacityはportableなlogical unitで表し、filesystem block、SQLite page、allocator overheadを使用しません。

```text
logical_entry_bytes = 16 + key_length + value_length
used_entries        = committed live key count
used_bytes          = Σ logical_entry_bytes(committed live keys)
available_entries   = max_entries - used_entries
available_bytes     = max_bytes - used_bytes
```

規則:

- `16`はportable accounting overheadであり、wire/storage encodingではありません。
- replaceのstaged deltaは`new logical_entry_bytes - old logical_entry_bytes`です。
- eraseの負deltaはcommit後にだけfree capacityへ反映します。同じtransaction内のpositive/negative deltaはnetで検査できます。
- active transactionのstaged mutationは別transactionへfree capacityとして見せません。
- key/valueを同じ内容で置換してもentry countは増えません。
- Runtimeがjournal/outbox等の将来枠として予約するbytes/entriesは、committed reservation recordとCoreのresource ledgerで別に数えます。providerがremote capacityを予約したと表示してはなりません。
- `capacity`は12章の`ninlil_storage_capacity_t.max_entries / used_entries / max_bytes / used_bytes`を同一snapshotから返します。available valuesは上式でchecked derivationし、underflowならcorruptionです。
- storage entry limitとRuntimeのrecord/resource limitは別です。Coreは両方の小さい方を超えてadmitしません。
- `max_entries`/`max_bytes`をunknown、0、`UINT64_MAX`にしてM1aをadmitしてはなりません。物理freeが取得不能なことは許可しますが、configured logical maximaは有限でなければなりません。
- logical limit超過、SQLite `FULL`、ENOSPCは、非commitを確定できる場合`NINLIL_STORAGE_NO_SPACE`です。
- lock/busyは`NINLIL_STORAGE_BUSY`、general I/Oは`NINLIL_STORAGE_IO_ERROR`、integrity corruptionは`NINLIL_STORAGE_CORRUPT`、commit結果不明は`NINLIL_STORAGE_COMMIT_UNKNOWN`へ写像します。
- physical fullがlogical headroom内で発生する可能性を隠してはなりません。reference portはheadroomを持ち、発生時は新規admissionを停止します。

## Typed simulated bearer contract

### Public boundary

M1a bearerは12章の`ninlil_bearer_message_t`、`ninlil_bearer_state_t`、`ninlil_bearer_send_result_t`と、`open`、`close`、`send`、`receive_next`、`release_received`、`state`を使用します。

これはlogical envelopeのtransportであり、public radio frame formatではありません。simulatorがC struct memoryを送る、`memcpy`したpaddingをdigestへ含める、将来のwire encoderとして公開することは禁止です。

### Logical messageとidentity

Typed messageは12章のfieldにより、最低限次を明示します。

- message kind: `NINLIL_BEARER_MESSAGE_APPLICATION`、`RECEIPT`、`DISPOSITION`、`CANCEL_REQUEST`、`CUSTODY_ACCEPTED`、`CANCEL_RESULT`
- transaction ID。admitted logical operationで不変
- event ID。EventFactの場合に不変
- attempt ID。1回のlogical send attemptで不変
- source runtime/application/local identity(device/installation/site/epochs)、target runtime/application/device/logical installation
- site、membership epoch、binding epoch
- inline `ninlil_text_id_t` service namespace/ID/schema、descriptor revision/digest、family/version
- content digest、generation、deadline clock epoch、absolute effect deadline、evidence grace
- required/receipt evidence、Disposition、effect certainty、retry guidance、cancel result、relative `retry_delay_ms`、Receipt evidence time、bounded payload/evidence

`send`が`NINLIL_BEARER_OK`かつaccepted kindを返す前に、providerは全value fieldとpayload/evidence viewのbyteをdeep-copyします。Inline text IDは`length`までのactual bytesだけがsemanticで、unused array bytesはzero必須です。callerはreturn後すぐ入力bufferを破棄・変更できます。

### Attempt、duplicate、retry

- 1回のCore `send`は1つのattempt IDを持ちます。
- network duplicateとして同じsendをN copies配送するとき、transaction ID、event ID、attempt ID、content digestを維持します。copyごとのharness delivery ordinalだけが異なります。
- Coreがloss、timeout、Disposition後にlogical retryするときは、同じtransaction/event IDと新しいattempt IDを使用します。
- M1a typed bearerにはphysical frame nonceを定義しません。07章`NIN-INV-005`のattempt ID部分はM1a必須、frame nonce部分はM5 protected wireから必須です。
- corruption faultは選択fieldまたはbyteを変更し、元のcontent/envelope binding digestを更新しません。receiverがinvalid inputとして拒否できる形にします。

### Send result、receive、custody

- `send`のacceptは「simulated bearerがbounded local queueへcopyを受け取った」というObservationだけです。remote delivery、application Receipt、required evidence、transaction successを意味しません。
- `send`のport statusが`NINLIL_BEARER_OK`の場合だけ、`out_result.kind`は`NINLIL_BEARER_SEND_ACCEPTED`または`NINLIL_BEARER_SEND_DURABLE_CUSTODY`です。後者もApplication Receiptではありません。
- queue full/temporary carrier busyは`NINLIL_BEARER_WOULD_BLOCK`、receiver/path unavailableは`NINLIL_BEARER_UNAVAILABLE`、permit denialは`NINLIL_BEARER_DENIED`です。これらではBearerがmessage ownershipを取得しません。
- `NINLIL_BEARER_LOST_UNKNOWN`ではBearerがmessageを保持しませんが、Coreはdelivery可能性を排除しません。
- `receive_next`はdueになったmessageを1件だけ返します。messageがなければ`NINLIL_BEARER_EMPTY`を返し、out messageをzero/invalidのままにして待ちません。
- 受信messageは`release_received`までprovider所有です。Coreは保持する場合、自身のbounded ingress/storageへcopyします。
- `release_received`はcustody acceptanceではありません。provider bufferのreleaseだけです。
- `NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED`はreceiverがpayloadと必要metadataを`FULL` commitした後にだけ生成できます。
- senderはcustody acceptanceをdurable commitし、serviceのcustody release policyが許可した後だけlocal payloadを解放できます。
- M1a EventFact fixtureのcustody policyは`NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE`です。transport custodyだけでorigin spoolを解放してはなりません。
- Receiptはpositive evidenceだけ、Delivery Dispositionはnegative/retry resultだけを表します。

### Message kind, orientation, and reply-binding vectors

12章の6-kind matrixを全row検査します。全kindでflags=0、transaction/source/target/service/content/required evidence/family/deadline bindingはoriginal admitted APPLICATIONから導出し、unused fieldをzero/emptyにします。

| Kind | Orientation / attempt | Kind-specific required values |
| --- | --- | --- |
| `NINLIL_BEARER_MESSAGE_APPLICATION` | forward / non-zero new attempt | exact payload、receipt/disposition/certainty/cancel NONE、guidance NEVER、delay 0、evidence/time empty |
| `NINLIL_BEARER_MESSAGE_RECEIPT` | reverse / triggering attempt echo | supported non-zero receipt stage、valid evidence time、0〜128 evidence bytes、payload empty |
| `NINLIL_BEARER_MESSAGE_DISPOSITION` | reverse / triggering attempt echo | DV1〜DV11のexact disposition/certainty/guidance/delay、payload/evidence/time empty |
| `NINLIL_BEARER_MESSAGE_CANCEL_REQUEST` | forward / non-zero cancel attempt | DesiredStateだけ、original Application attemptとは別の1回限りID、cancel kind 0、payload/evidence/time empty |
| `NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED` | reverse / triggering attempt echo | application evidenceではない。他のkind-specific fieldはzero/empty |
| `NINLIL_BEARER_MESSAGE_CANCEL_RESULT` | reverse / triggering cancel attempt echo | DesiredStateだけ、known non-zero cancel kind、payload/evidence/time empty |

Vector `O1_C1_REVERSE_RECEIPT`はC1 APPLICATIONのattempt ID=`5dd9578bd99d35ff819efba06edcb33e`に対するAPPLIED Receiptです。Reverse source partyはruntime=`4100...0001`、application=`6000...0001`、local identity=`device 4000...0001 / installation 5000...0001 / site 1000...0001 / flags 7 / epochs 1,1`です。Reply targetはruntime=`2100...0001`、application=`3000...0001`、device=`2000...0001`、installation=`5000...0002`、site=`1000...0001`、flags=7、binding/membership epoch=1です。

O1はtransaction、attempt、service descriptor revision/digest、content digest、generation=1、deadline epoch=`a000...0001`、absolute deadline、grace、required evidenceをC1 APPLICATIONとbyte/value一致でechoし、receipt stage=APPLIED、evidence time=`a000...0001 / 500 / TRUSTED`、empty payloadを持ちます。Receiverのresult commit前には生成できず、senderは全binding検証後にだけReceipt reducerへ入力します。

Vector `O2_C1_REMOTE_CANCEL_SINGLE_PREPARE`はC1 Application delivery可能性を記録後にpublic cancelを呼びます。ControllerはApplication attemptとは別のcancel attempt ID=`836926954fc0c8111965b6c4ff3f369e`（C1 stream block 3）、prepared record、immutable forward CANCEL_REQUEST、send gate=`NEVER_INVOKED`を`FULL` commitします。Cancel allocation/prepare成功はtransaction lifetimeでexactly 1回、candidate entropy Port callはID1〜ID3と同じ最大4回です。Bearer send invocationだけは下記definite-WOULD_BLOCK ruleの範囲で同じattempt/messageを再実行できます。Endpointのreverse CANCEL_RESULTは同じcancel attemptをechoします。

| Variant | Send-gate sequence | Required result |
| --- | --- | --- |
| `O2A_WOULD_BLOCK_REINVOKE` | NEVER_INVOKED → fresh permit → pre-send `INVOKED_CLOSED` FULL commit → send returns definite no-accept WOULD_BLOCK → `WOULD_BLOCK_RETRYABLE` FULL commit | unused permitをreleaseし、次回fresh permitで同じattempt ID/immutable messageを再invoke可。再度WOULD_BLOCKなら繰返し可 |
| `O2B_NON_WOULD_BLOCK_CLOSES` | pre-send close後、OK accepted/custody、LOST_UNKNOWN、UNAVAILABLE、DENIED、CORRUPT、invalid EMPTY/partial OK、またはpossible-delivery observation | `INVOKED_CLOSED`をterminalまで維持。Result未達、timeout、restartでもrequest reinvoke/new attempt 0 |
| `O2C_CRASH_FENCE` | pre-send commit unknown、commit OK後send前crash、send return後observation/reopen commit前crash | conservatively `INVOKED_CLOSED`。送信しなかったと推測せずreinvoke 0 |
| `O2D_REOPEN_COMMIT_FAILURE` | definite WOULD_BLOCK後の`WOULD_BLOCK_RETRYABLE` commitがdefinite failure/unknown | gateはclosed、reinvoke 0。WOULD_BLOCK returnだけでvolatile reopenしない |
| `O2E_REPLAY_API` | repeated public cancel API / Runtime restart | new cancel ID、entropy、prepare 0。persist済みPENDING_REMOTE_FENCEまたはcached terminal cancel result |

`O2F_CANCEL_PUBLIC_ALL_FIELDS`はout resultをnon-zero poisonで埋め、12章の4-kind matrixを検査します。Local pre-dispatch fenceは`FENCED / CANCEL_FENCED / CANCELLED`、first remote prepareは`PENDING / CANCEL_PENDING / NONE`、cancel recordなしの既存SATISFIED transactionは`ALREADY_TERMINAL / REQUIRED_EVIDENCE_MET / SATISFIED`です。PENDING後にrequired ReceiptでSATISFIEDとなったrepeatは`PENDING / CANCEL_PENDING / SATISFIED`、TOO_LATE後にOUTCOME_UNKNOWNとなったrepeatは`TOO_LATE / CANCEL_AFTER_EFFECT_POSSIBLE / OUTCOME_UNKNOWN`です。Cancel自身でterminal化したrepeatはFENCEDのままで、ALREADY_TERMINALへ変えません。各repeatでnew attempt/entropy/send/storage mutationは0です。

各pre-send closeとWOULD_BLOCK reopenは`controller.before_cancel_send_gate_commit` / `controller.after_cancel_send_gate_commit`、Bearer return直後は`controller.after_cancel_bearer_send`をexactly通ります。Before-hook crashでcommit未実行ならprior durable gateを保持し、after hookは発生しません。Prior gateがNEVER_INVOKED/WOULD_BLOCK_RETRYABLEである場合だけ、recoveryはfresh permit取得と新しいpre-send closeから再開できます。Permitはmessage bindingの一部ではありませんが各invocationでfresh valueとし、CANCEL_REQUESTの全semantic byte/valueは不変です。

Processが生存しているno-send pathでは未消費permitを`release_unused`し、crash pathではprovider expiry/restart invalidationへ委ねて同permitを再利用しません。Pre-send closeがdefinite failure/unknown、またはclose OK後send前crashならBearer invocation 0でもfail-closedであり、「送っていないはず」を根拠にgateをreopenしません。

Orientation negative vectorsはO1から次を1つずつ変更します。

- forward source/targetをそのままReplyに使う
- reverse source local identityのdevice、installation、site、flags、binding epoch、membership epochのいずれか1つ
- reply targetのruntime/application/local identityのいずれか1つ
- attempt IDをall-zero、別attempt、または別transactionのknown attemptへ変える
- transaction、service identity/revision/digest、content digest、family、generation、deadline epoch/time、grace、required evidenceのいずれか1つ
- Receiptへpayload/disposition/cancelを追加、Dispositionへevidence time/evidenceを追加、CANCEL kindでattemptをzero、Application attemptを再利用、またはrequest/result間で変える
- EventFactへCANCEL kind、Commandへnon-zero event IDを使用する

各mutationは`receive_next` bufferをreleaseしますが、durable ingress、transaction/evidence state、result cache、retry timer、callback invocation、reply sendをすべて0件のままにします。不正messageへReceipt/Dispositionで応答せずinvalid-ingress diagnosticだけをboundedに増やします。Unknown kind/enum、non-zero reserved/flagsも同じpre-reducer rejectionです。

### Virtual TxPermit

M1a simulated bearerもTx Gateをbypassしません。`TEST`環境の`ninlil_tx_gate_ops_t`はone-shot virtual permitを発行します。

Public `ninlil_tx_permit_t`は12章どおりpermit ID、attempt ID、clock epoch ID、expiryを持ちます。TEST Tx Gate/Bearerが共有するprovider内部permit tableは、次へbindingします。

- permit IDとissuer ID
- transaction ID
- attempt ID
- message kind
- content digest
- accounted message bytes
- acquire clock epoch/時刻と`expires_at_ms`
- strictly monotonic permit sequence

規則:

- permitなし、別transaction/attempt/kind/digest/size、current clock epoch不一致、`now_ms >= expires_at_ms`、`release_unused`済み、再利用は`NINLIL_BEARER_DENIED`です。Expiry endはexclusiveです。
- permitは`send`がqueue ownershipを受理した瞬間に1回だけconsumeします。
- queue fullまたは`NINLIL_BEARER_WOULD_BLOCK`でmessageを受理しなかった場合はconsumeしません。ただしexpiryは進みます。Coreが送信を断念する場合は`release_unused`を1回呼びます。
- drop/duplicate/delay faultはpermit消費後のnetwork挙動です。duplicate copyごとに新permitを要求しません。
- unknown environment、`FIELD_PILOT`、`PRODUCTION`でvirtual issuerをloadしたRuntimeは起動を拒否します。
- virtual permitはairtime、frequency、LBT、出力、認証を検査しません。physical complianceの証拠ではありません。
- permit valueのportable logical sizeは`permit ID 16 + attempt ID 16 + clock epoch ID 16 + expiry 8 = 56 bytes`です。Provider内部request binding/allocator overheadは別のbounded provider resourceとして数え、Bearer envelope bytesへ加えません。

### Bearer queue accounting

すべてのM1a bearer実装は、C struct sizeではなく次のlogical accountingを使用します。

```text
envelope_bytes =
    455
  + namespace_length
  + service_id_length
  + schema_id_length
  + payload_length
  + evidence_length
```

`455`は12章`ninlil_bearer_message_t`の全固定semantic fieldを、ABI header/pointer/paddingとinline text IDのunused capacityを除いて次の幅で数えたportable constantです。

```text
kind/flags                                      8
transaction/attempt/event IDs                  48
source runtime/application/local identity     100
target runtime/application/device/install/site 80
target binding/membership epochs + flags       20
3 inline text length fields                     3
descriptor revision/digest/schema/family       52
content digest                                 36
generation/deadline epoch/deadline/grace       40
evidence/disposition/effect/retry/cancel       24
retry delay                                     8
evidence time(epoch/now/trust)                 28
payload/evidence length fields                  8
total                                          455
```

Digestはalgorithm/reserved/32 bytesの36 bytes、`evidence_time`はepoch ID 16 + now 8 + trust 4の28 bytesとして数え、reserved/headerを除きます。各`ninlil_text_id_t`はlength byte 1 + actual text bytesだけを数え、63-byte arrayのunused capacityは数えません。unused ID/enum/view/sampleは12章どおりzero/emptyですが固定field分は数えます。これはwire encodingではありません。`ninlil_tx_request_t.logical_bytes`、bearer queue、runtime ingress queueは同じ`envelope_bytes`を使用します。

- queue entry countはmessage copyごとに1です。
- queued byte countは各copyの`envelope_bytes`の和です。
- duplicate N copiesは、元の1 copyを含む合計N entriesとして各copyを計上します。
- duplicate faultのcopy数は`send` acceptance前にcapacity計算へ展開します。全copiesがentry/byte limitへ収まらなければ`NINLIL_BEARER_WOULD_BLOCK`、enqueue 0、permit未消費です。Senderへacceptを返した後のpartial duplicate failureは禁止します。
- queueへ入る前にdropしたcopyは計上せず、queue受理後にdropしたcopyはdrop eventまで計上します。
- entryまたはbyteのどちらか一方でもlimit超過なら受理しません。partial enqueueは禁止です。
- actual heap/allocator使用量は別のbounded allocator limitで検査します。logical headroomがあってもallocation failureを成功へ変換しません。
- default Foundation fixtureは方向ごとに64 entries、131,072 logical bytesです。scenarioはこれより小さくできますが、実行中に無通知で変更しません。

Fixture accounting vectors: C1 APPLICATION=`455 + 19 + 14 + 14 + 9 = 511 bytes`、E1 APPLICATION=`455 + 19 + 13 + 13 + 10 = 510 bytes`です。C1を2-copy duplicateするqueue reservationは2 entries/1,022 bytesで、1 entryだけ入れるpartial acceptanceは禁止します。

## Clock port contract

### Monotonic time

`ninlil_clock_ops_t.now`は`ninlil_port_status_t`と`ninlil_time_sample_t`を返します。

- `NINLIL_PORT_OK`時だけsampleがvalidです。`clock_epoch_id`はnon-zero、`trust`は`NINLIL_CLOCK_TRUSTED`または`NINLIL_CLOCK_UNCERTAIN`です。
- 同じ`clock_epoch_id`では`now_ms`が減少しません。同じ値を複数回返せます。
- restartを跨ぐ同一timelineを証明できるportは同じepoch IDを返します。epoch変更はelapsed time continuityを証明しません。
- M1a deadlineはwall clock、timezone、NTP表示時刻ではなくこのlogical monotonic timeで計算します。
- Runtimeはresource reservation/storage transaction開始前にtrusted clockを1回sampleし、これを`admission reference sample`とします。`admitted_at_ms`と`admission_clock_epoch_id`はこの**pre-commit** sampleで、commit acknowledgement時刻へ上書きしません。
- `effect_deadline_at = admitted_at_ms + effect_deadline_ms`と`evidence_close_at = effect_deadline_at + evidence_grace_ms`はcommit前のchecked additionです。overflowはadmission rejectです。Sample、absolute timer、Submission/descriptor/source/target bindingを同じadmission `FULL` transactionへpersistします。
- Sample/staged writeだけではownership/assurance/transaction sequence/ADMITTEDは成立せず、commit OKでだけ成立します。Definite failureはcaller ownership、unknownは`NINLIL_E_STORAGE_COMMIT_UNKNOWN`です。
- `NINLIL_NO_DEADLINE`は時刻値として加算しません。
- rebootを跨ぐelapsed timeをport/profileが証明できない場合、推測したtrusted sampleを返してはなりません。new epochまたはuncertain trustを返し、Coreは`NINLIL_E_CLOCK_UNCERTAIN`と13章のconservative recoveryへ進みます。

### Virtual clock

- harnessの`sim_time_ms`は0から始まり、自動では進みません。
- event queueから次eventをpopするときだけ、その`due_time_ms`へ進みます。
- `sim_time_ms`は減少しません。過去時刻へscript/bearer eventをscheduleしようとした場合はcurrent timeへclampせずscenario errorにします。Clock forward jumpで既にdueとなったRuntime timerだけは、下記規則でcurrent timeへenqueueします。
- Runtime restart、storage reopen、partition解除で時刻を0へ戻しません。
- virtual `now`は`NINLIL_PORT_OK`とharness timeを返します。正常fixtureのepoch IDは`a0000000000000000000000000000001`で、Runtime restartでは変えません。wall clock APIはありません。
- 各runtime clock providerは`offset_ms`を持ち、trusted時のsampleは`checked(sim_time_ms + offset_ms)`です。normal fixtureのoffsetは0です。
- forward jump faultはruntime-local clock viewを前へ進められますが、global scheduler event orderを飛び越しません。backward/rollback faultはscheduler timeを戻さずnew clock epoch + uncertain trustへ変え、Runtimeへ`CLOCK_UNCERTAIN` inputを与えます。
- forward jumpはoffsetを増やした同じscript actionからcurrent-time runtime wakeをenqueueします。そのwakeで新`now`以下になった全logical timerを13章priorityで処理し、旧pending timer generationをcancelします。Clock time `T`のfuture wakeは同じepoch/offsetで`T - offset_ms`をglobal due timeへ変換し、結果がcurrent sim time未満ならcurrent timeにenqueueします。
- trustを明示的なrecovery actionなしに自動回復しません。

Vector `T0_ADMISSION_COMMIT_CROSSES_DEADLINE`はC1 admission referenceをepoch=`a000...0001`, now=0としてdeadline=5,000/evidence close=6,000をstagedします。Scripted clock/storage boundaryによりadmission `FULL` commitはOKですが、commit後の最初のtrusted sampleは同epoch now=5,000です。

- Snapshotは`admitted_at_ms=0`、deadline=5,000のままで、commit acknowledgement時刻5,000へ書き換えません。
- Submitは既に所有したtransactionの`NINLIL_SUBMISSION_ADMITTED_READY`を返し、commit中にdeadlineへ達したことをREJECTEDへ巻き戻しません。
- Dispatch前guardは`now >= deadline`として`controller.before_deadline_terminal_commit` / `controller.after_deadline_terminal_commit`を通る次の`FULL` commitで`NINLIL_OUTCOME_EXPIRED + NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH`へterminalizeします。Attempt ID draw、ATTEMPT_PREPARE、TxPermit、Bearer sendは0です。
- Admission commit直後にcrashしたvariantもrecovery fence後の最初のguardで同じterminalへ収束します。Terminalization commitがdefinite failure/unknownならsend 0のままrecoveryし、EXPIRED successを先に公開しません。

### Receipt evidence-time vectors

`ninlil_bearer_message_t.evidence_time`はReceipt issuerがapplication result/ingress evidenceをdurable commitしたlogical timeです。Receipt以外ではnested struct全体をzeroにします。DesiredStateCommandの全message kindはadmission時のnon-zero `deadline_clock_epoch_id`とabsolute deadlineを保持し、EventFactではepoch ID zero、deadline=`NINLIL_NO_DEADLINE`です。

Fixture C1は`admitted_at_ms=0`、deadline clock epoch=`a0000000000000000000000000000001`、absolute effect deadline=`5000`、evidence close=`6000`とします。Clock profileが直接比較可能と宣言するのは同じepoch IDだけで、uncertaintyは0です。

| Vector | Receipt evidence time | Controller durable ingress | Required result |
| --- | --- | ---: | --- |
| `T1_SHARED_EPOCH` | epoch=`a000...0001`, now=4500, `NINLIL_CLOCK_TRUSTED` | 5200 | evidence timeで期限内を証明し、APPLIED commit後`NINLIL_OUTCOME_SATISFIED` |
| `T2_EPOCH_MISMATCH` | epoch=`a000...0002`, now=4500, `NINLIL_CLOCK_TRUSTED` | 5200 | issuer timeを比較せずingressへfallback。期限内を証明できず、grace closeで`NINLIL_OUTCOME_UNKNOWN` |
| `T3_UNCERTAIN_ISSUER` | epoch=`a000...0001`, now=4500, `NINLIL_CLOCK_UNCERTAIN` | 5200 | T2と同じ。trustedへ格上げしない |
| `T4_EVENT_AUDIT_ONLY` | epoch=`a000...0001`, now=4500, `NINLIL_CLOCK_TRUSTED` | 5200 | EventFactのaudit evidenceとして保持。deadline判定を生成しない |

FallbackはReceiptのpositive stageを捨てる規則ではありません。latest evidenceをcommitしつつ、比較不能なissuer timeだけでdeadline verdictを`MET`へしてはなりません。Controller ingress timeがdeadline以下なら、その時刻を保守的な期限内証明に使用できます。

## Entropy port contract

### ProductionとTESTの分離

- non-simulator POSIX portはOS CSPRNGからrequested bytesを全量取得します。partial outputをsuccessとして返しません。
- deterministic providerは`TEST` artifactだけにlinkします。生成byteはsecret、credential、production nonceに使用できません。
- entropy failure時にzero、clock、device ID、PRNG fallbackを使用してsuccessを返してはなりません。Providerは`NINLIL_PORT_TEMPORARY_FAILURE`または`NINLIL_PORT_PERMANENT_FAILURE`を返し、Coreが`NINLIL_E_ENTROPY`へ写像します。

### Deterministic entropy v1

Fault scriptの`seed`はlowercase 16-hex-digitのunsigned 64-bit値です。各runtime fixtureは明示的なunique `stream_id`を持ちます。

```text
block(counter) = SHA-256(
    ASCII("ninlil-sim-entropy-v1")
    || seed_u64_big_endian
    || stream_id_u32_big_endian
    || counter_u64_big_endian)
```

- counterは0から始まります。
- 1回の`fill(n)`はcounter順に`ceil(n / 32)` blocksを連結し、先頭n bytesを返します。
- 最後のblockの未使用byteは破棄します。次callは次counterから開始します。
- n=0は`NINLIL_PORT_OK`でcounterを進めません。
- counter overflowはproviderの`NINLIL_PORT_PERMANENT_FAILURE`であり、Coreでは`NINLIL_E_ENTROPY`です。
- metrics epoch/transaction/attempt ID candidateは取得した16 bytesをそのままID byte orderとして使用します。Event/operation IDはcaller-suppliedでこのstreamを消費しません。All-zeroでもproviderは書き換えずCoreが全3種で拒否します。Collision validationはtransaction/attemptだけで、metrics epochは保持indexのないfresh observability labelとして扱います。
- Runtime restartでcounterを戻しません。harnessがstream stateを保持します。完全なscenario resetだけがcounterを0へ戻します。
- `entropy_fail` faultは指定streamの次N callsを`NINLIL_PORT_TEMPORARY_FAILURE`にし、failed callではcounterを進めません。

Foundation fixtureのstream IDはharness=`0`、controller-1=`1`、endpoint-1=`2`です。追加runtimeはscenario manifestで明示し、自動割当しません。

Seed=`0123456789abcdef`の`block(0)` golden value:

```text
stream 0: 7ad714f1260c1fd750efd7209bc0cd6d08b69ebfc2e40f173273b731dbf6929e
stream 1: 968198a87ecbad2092b55f929da076a3d59d6963afba9d8212a061bb7684c08f
stream 2: 4faf7975a1ca8185196dcb80ccd0bfa1560ca72056449276ae8a723f8f7f4033
```

### Foundation ID-consumption golden order

C1とE1は**別scenario reset**として実行し、seed、全stream counter、store、queueをそれぞれ初期状態へ戻します。Origin Runtimeは各IDに`fill(16)`を1回使い、block後半16 bytesを破棄します。Foundation golden pathの消費順は(1) Runtime createのmetrics epoch、(2)新規admissionのtransaction ID、(3)最初のApplication attempt IDです。別のnonce、temporary ID、container seedを間へ挿入してはなりません。

| Scenario / stream | Counter / use | Full independently calculated block | ID = first 16 bytes |
| --- | --- | --- | --- |
| C1 / controller 1 | 0 / metrics epoch | `968198a87ecbad2092b55f929da076a3d59d6963afba9d8212a061bb7684c08f` | `968198a87ecbad2092b55f929da076a3` |
| C1 / controller 1 | 1 / transaction | `0d5382f07b9c59639f7c1957ae22fea7742b0b44e855d011ffd887ffe7e89cd3` | `0d5382f07b9c59639f7c1957ae22fea7` |
| C1 / controller 1 | 2 / attempt 1 | `5dd9578bd99d35ff819efba06edcb33e5b708be5e5302aa2b33740a6adba9ee3` | `5dd9578bd99d35ff819efba06edcb33e` |
| C1 / controller 1 | 3 / optional remote-cancel attempt | `836926954fc0c8111965b6c4ff3f369e79674abbfd1ea72f32285482b17a79bf` | `836926954fc0c8111965b6c4ff3f369e` |
| E1 / endpoint 2 | 0 / metrics epoch | `4faf7975a1ca8185196dcb80ccd0bfa1560ca72056449276ae8a723f8f7f4033` | `4faf7975a1ca8185196dcb80ccd0bfa1` |
| E1 / endpoint 2 | 1 / transaction | `a0726cd8b13d4cab041a06a5fce92ca4f1d01fb88d22d27e56f73446eeb2c4f4` | `a0726cd8b13d4cab041a06a5fce92ca4` |
| E1 / endpoint 2 | 2 / attempt 1 | `a8c780783f852e11cb4fdd5188d44ffcc3264bd601e0dcbff08d9e623999f69e` | `a8c780783f852e11cb4fdd5188d44ffc` |

C1 traceのtransaction-scoped recordはsubject ID=`0d5382f07b9c59639f7c1957ae22fea7`、最初のattempt-scoped recordはattempt ID=`5dd9578bd99d35ff819efba06edcb33e`です。E1はそれぞれ`a0726cd8b13d4cab041a06a5fce92ca4`と`a8c780783f852e11cb4fdd5188d44ffc`です。Metrics snapshotはblock 0、submit/query/listのtransaction IDはblock 1、typed message/permit request/attempt-scoped traceはblock 2のfirst 16 bytesへそれぞれ一致しなければなりません。

Crash/restartはstream counterを戻しません。Exact duplicate submissionは既存transactionへ収束するためnew transaction IDを消費せず、logical retryだけが次のvalid attempt candidateを消費します。Golden testは上表のblockをRuntime出力から逆算せず、独立SHA-256実装で生成して比較します。

Transaction ID reducer vectorsはSubmissionの全non-entropy guard/preflight成功後だけ開始します。

- `TXID1_FOURTH_VALID`: draw 1=all-zero、2=retained transaction collision、3=partial fill、4=valid non-zero unique。4件をordinal付き`TRANSACTION_ID_DRAW_RESULT`としてreduceし、4th IDだけをsequence/mapping/admissionと同じFULL commitへ含めます。最初の3件でreservation/storage/ownership/index mutationは0です。
- `TXID2_FOUR_INVALID`: Port failure、partial、all-zero、collisionを4件で使い切る。APIは`NINLIL_E_ENTROPY`、Submission result INVALID/reason NONE/zero IDs/digest/assurance、transaction/mapping/sequence/reservation/storage mutation 0、Runtime healthはDEGRADED / `OUTCOME_UNKNOWN`です。5th drawを呼びません。
- `TXID3_STORAGE_LOOKUP_FAILURE`: collision index lookupがBUSY/IO/CORRUPTを返す。Entropy budgetへ「invalid candidate」として吸収せず対応Storage statusでfail closedし、後続draw/admission commit 0です。

## Fault hook contract

### Hook execution

- hook nameは12章§17のNamed fault hook registry 130件を正確に使用します。任意文字列をsilent ignoreしません。Registry追加/削除時は下記mirrorとの差分をCI failureにします。
- hookはproduction control flow上の境界へ置きます。test専用shortcutで本来のcommit/orderを迂回してはなりません。
- production buildではhook dispatchをcompile outできますが、hook有無でtransaction境界を変えてはなりません。
- hook occurrenceは`runtime_id + hook_name`ごとに1から数えます。hookへ到達した時点でincrementし、action後にcrashしても戻しません。
- hook contextはruntime ID、hook name、occurrence、sim time、operation ID、transaction/attempt IDのうち存在する値をimmutable viewとして渡します。
- hook callbackはCoreへ再入しません。Hook-triggered `crash_runtime`だけはqueueへ通常eventを積まず、そのhook dispatchからsimulated nonlocal abortを即時発生させます。Current Core/public callの残処理、対応after hook、Storage commit/send/callback、public return、graceful cleanupを実行しません。`restart_after_ms`があればcrash時点からrestart eventだけをscheduleします。`storage_status`等のnext-operation faultはprovider stateを同期設定してCore callを継続します。Time-triggered `crash_runtime`はevent queue上で実行し、すでに完了したCore callを遡って中断しません。

### Closed hook registry mirror

次の130行は12章§17と順序・文字列ともexact一致するmachine-compared mirrorです。Comment、alias、prefix wildcardはregistry要素ではありません。

<!-- HOOK_REGISTRY_MIRROR_BEGIN -->
```text
runtime.before_service_registry_commit
runtime.after_service_registry_commit
runtime.before_ingress_copy_commit
runtime.after_ingress_copy_commit
runtime.before_bearer_state_commit
runtime.after_bearer_state_commit
runtime.before_reverse_send_observation_commit
runtime.after_reverse_send_observation_commit
runtime.before_retention_basis_commit
runtime.after_retention_basis_commit
runtime.before_namespace_binding_commit
runtime.after_namespace_binding_commit
runtime.before_identity_rotation_commit
runtime.after_identity_rotation_commit
controller.before_admission_begin
controller.after_transaction_put
controller.after_roster_put
controller.after_reservation_put
controller.after_idempotency_put
controller.after_outbox_put
controller.before_admission_commit
controller.after_admission_commit
endpoint.before_event_admission_begin
endpoint.after_event_transaction_put
endpoint.after_event_key_mapping_put
endpoint.after_event_id_mapping_put
endpoint.after_event_grant_put
endpoint.after_event_spool_put
endpoint.before_event_admission_commit
endpoint.after_event_admission_commit
controller.before_attempt_prepare_commit
controller.after_attempt_prepare_commit
controller.after_bearer_send
controller.before_application_send_observation_commit
controller.after_application_send_observation_commit
endpoint.before_attempt_prepare_commit
endpoint.after_attempt_prepare_commit
endpoint.after_bearer_send
endpoint.before_application_send_observation_commit
endpoint.after_application_send_observation_commit
controller.before_cancel_prepare_commit
controller.after_cancel_prepare_commit
controller.before_cancel_send_gate_commit
controller.after_cancel_send_gate_commit
controller.after_cancel_bearer_send
controller.before_receipt_commit
controller.after_receipt_commit
endpoint.before_receipt_commit
endpoint.after_receipt_commit
controller.before_receipt_send
endpoint.before_receipt_send
controller.before_disposition_commit
controller.after_disposition_commit
endpoint.before_disposition_commit
endpoint.after_disposition_commit
controller.before_custody_send
endpoint.before_custody_send
controller.before_command_attempt_timeout_commit
controller.after_command_attempt_timeout_commit
controller.before_evidence_close_commit
controller.after_evidence_close_commit
controller.before_deadline_terminal_commit
controller.after_deadline_terminal_commit
controller.before_delivery_ingress_commit
controller.after_delivery_ingress_commit
endpoint.before_delivery_ingress_commit
endpoint.after_delivery_ingress_commit
controller.before_delivery_started_commit
controller.after_delivery_started_commit
endpoint.before_delivery_started_commit
endpoint.after_delivery_started_commit
controller.before_application_callback
controller.after_application_effect
controller.after_application_callback
endpoint.before_application_callback
endpoint.after_application_effect
endpoint.after_application_callback
controller.before_callback_recovery_commit
controller.after_callback_recovery_commit
endpoint.before_callback_recovery_commit
endpoint.after_callback_recovery_commit
controller.before_result_cache_commit
controller.after_result_cache_commit
endpoint.before_result_cache_commit
endpoint.after_result_cache_commit
controller.before_token_timeout_commit
controller.after_token_timeout_commit
endpoint.before_token_timeout_commit
endpoint.after_token_timeout_commit
controller.before_reconcile_callback
controller.after_reconcile_callback
controller.before_reconcile_commit
controller.after_reconcile_commit
endpoint.before_reconcile_callback
endpoint.after_reconcile_callback
endpoint.before_reconcile_commit
endpoint.after_reconcile_commit
endpoint.before_cancel_tombstone_commit
endpoint.after_cancel_tombstone_commit
endpoint.before_cancel_result_send
controller.before_cancel_result_commit
controller.after_cancel_result_commit
endpoint.before_event_attempt_timeout_commit
endpoint.after_event_attempt_timeout_commit
endpoint.before_event_park_commit
endpoint.after_event_park_commit
endpoint.before_event_availability_resume_commit
endpoint.after_event_availability_resume_commit
endpoint.before_event_resume_commit
endpoint.after_event_resume_commit
endpoint.before_event_discard_commit
endpoint.after_event_discard_payload_erase
endpoint.after_event_discard_commit
runtime.after_commit_unknown_observed
runtime.before_destroy_recovery_commit
runtime.after_destroy_recovery_commit
runtime.before_storage_reopen
runtime.after_storage_reopen
runtime.before_recovery_scan
runtime.after_recovery_scan
runtime.before_recovery_item_commit
runtime.after_recovery_item_commit
runtime.before_terminal_cleanup_commit
runtime.after_terminal_cleanup_commit
runtime.before_result_cache_cleanup_commit
runtime.after_result_cache_cleanup_commit
runtime.before_token_tombstone_cleanup_commit
runtime.after_token_tombstone_cleanup_commit
runtime.before_capacity_epoch_commit
runtime.after_capacity_epoch_commit
```
<!-- HOOK_REGISTRY_MIRROR_END -->

CIは両章のcode blockからcomment/blankを除いた配列を抽出し、count=130、unique=130、ordered set equalityを検査します。文字列集合だけでなく順序も差分にします。

### Specific transition crash coverage

| Vector | Exact hook pair | Required convergence / no-hook negative |
| --- | --- | --- |
| `HC1_COMMAND_ACCEPTED_TIMEOUT` | `controller.before_command_attempt_timeout_commit` / `controller.after_command_attempt_timeout_commit` | R1C prior stateまたはAWAITING_EVIDENCE+EFFECT_POSSIBLEの一方。stale/Receipt-winning/Event timeoutはoccurrence 0 |
| `HC2_COMMAND_EVIDENCE_CLOSE` | `controller.before_evidence_close_commit` / `controller.after_evidence_close_commit` | R4 pre-close activeまたはOUTCOME_UNKNOWN terminalの一方。EventFact/先にterminalはoccurrence 0 |
| `HC3_DEADLINE_TERMINAL` | `controller.before_deadline_terminal_commit` / `controller.after_deadline_terminal_commit` | T0 admitted READYまたはEXPIREDの一方、send 0。Pre-admission rejection/既にattempt prepared済み通常deadlineはoccurrence 0 |
| `HC4_CONTROLLER_CALLBACK_RECOVERY` | `controller.before_callback_recovery_commit` / `controller.after_callback_recovery_commit` | F1〜F3のactive started markerまたはtoken-invalidated RECOVERY_REQUIREDの一方、Receipt 0 |
| `HC5_ENDPOINT_CALLBACK_RECOVERY` | `endpoint.before_callback_recovery_commit` / `endpoint.after_callback_recovery_commit` | F1〜F3 Controller variantと同じ。Reconcile resultはこのpair occurrence 0 |
| `HC6_CANCEL_SEND_GATE` | `controller.before_cancel_send_gate_commit` / `controller.after_cancel_send_gate_commit` | O2A〜O2D prior gateまたはcommit後gateの一方。Prepare commit/after Bearer returnは別hook |
| `HC7_SERVICE_REGISTRY` | `runtime.before_service_registry_commit` / `runtime.after_service_registry_commit` | SV1 registry absent/committedの一方。Recreate attach/exact reregisterはoccurrence 0 |
| `HC8_INGRESS_COPY` | `runtime.before_ingress_copy_commit` / `runtime.after_ingress_copy_commit` | INQ2 provider buffer未release+copy absent、またはdurable copy+sequence後releaseの一方。Semantic ingress commitは別hook |
| `HC9_BEARER_STATE` | `runtime.before_bearer_state_commit` / `runtime.after_bearer_state_commit` | AVP1 last-seen prior/new epochの一方。Exact same tuple/old/invalid/same-epoch flag conflict/budget0はoccurrence 0 |
| `HC10_REVERSE_OBSERVATION` | `runtime.before_reverse_send_observation_commit` / `runtime.after_reverse_send_observation_commit` | BS4 reverse state PENDING/WAITINGまたはclosed observationの一方。Crash before commitはduplicate-safe resend可 |
| `HC11_RETENTION_BASIS` | `runtime.before_retention_basis_commit` / `runtime.after_retention_basis_commit` | RET2〜RET4 basis pending/rebased/overflow markerの一方。Actual cleanupはcleanup-specific hook |
| `HC12_APPLICATION_SEND_OBSERVATION` | role-specific `before_application_send_observation_commit` / `after` | TxGate semantic no-sendまたはBearer return後、state/timer/cursorが未commitまたは全commit。Eventが同commitでPARKEDへ進むcaseもこのpairだけでevent-park pair 0。Bearer-return before crashはsame attempt replay、after crashはadditional send 0。Reverse/cancel occurrence 0 |
| `HC13_NAMESPACE_BINDING` | `runtime.before_namespace_binding_commit` / `runtime.after_namespace_binding_commit` | Profile/capacity/4 countersが全部absentまたは全部commit。Exact reopen/identity rotation occurrence 0 |
| `HC14_IDENTITY_ROTATION` | `runtime.before_identity_rotation_commit` / `runtime.after_identity_rotation_commit` | Old current identityまたはforward rotation全commit。Initial binding/exact/stale/device conflict occurrence 0 |
| `HC15_EVENT_OVERLAP_PRIMARY` | Receipt terminal、8th timeout park、Application send-result park、Disposition park、availability/manual resume、discardを各実行 | 12章overlap tableのprimary pair exactly1。Send-result parkはapplication observation、Disposition parkはevent park。Removed summary/release pair、secondary park/resume/cleanup pair occurrence 0 |

各before hookは全staged write後/`commit(FULL)`直前、after hookはcommit OK後/次side effect前です。Before crashでは対応after occurrence 0、commit unknown/definite failureでもafter 0です。After crashではcommit済みground truthからrecoveryし、callback、Bearer send、payload release、public successを二重実行しません。Recoveryが同じ未commit transitionを再実行するときもgeneric recovery hookへaliasせずspecific pairを再度通ります。

130 hookすべてについて「hook直前crash」と、after系では「hook直後crash」をsystematicに実行します。Pairのないput/send/callback/reopen/scan hookもmirror各行を独立scenarioとして到達させ、到達不能/余剰hookをrelease gate failureにします。

### Fault script schema v1

入力はstrict JSONです。top-level formは次です。

```json
{
  "schema": "org.ninlil.sim.fault-script/1",
  "scenario": "foundation-command-crash",
  "seed": "0123456789abcdef",
  "max_events": 100000,
  "events": [
    {
      "id": "crash-after-admission",
      "trigger": {
        "kind": "hook",
        "runtime": "controller-1",
        "name": "controller.after_admission_commit",
        "occurrence": 1
      },
      "action": {
        "kind": "crash_runtime",
        "runtime": "controller-1",
        "restart_after_ms": 10
      }
    }
  ]
}
```

Validation:

- `schema`、`scenario`、`seed`、`events`は必須です。`max_events`省略時は100,000です。
- objectのunknown field、unknown enum、duplicate event ID、duplicate JSON key、invalid UTF-8、number overflowをscenario load errorにします。
- triggerは`hook`または`time`のどちらか1つです。
- hook triggerは`runtime`、`name`、1-based `occurrence`が必須です。
- time triggerは`at_ms`が必須です。current timeより前には設定できません。
- event array indexを`script_index`とし、同じtriggerへ一致したactionはindex昇順でscheduleします。
- 一度fireしたscript eventはrestart後も再度fireしません。
- script全体とfixture manifestのSHA-256をscenario revisionとしてtraceへ残します。

### Action catalog

| `kind` | 必須field | 規範動作 |
| --- | --- | --- |
| `crash_runtime` | `runtime` | graceful destroyなしでvolatile instanceを失う。Hook triggerではdispatch地点からimmediate abort、time triggerではqueue eventとして実行。`restart_after_ms`は任意 |
| `storage_status` | `runtime`, `operation`, `status`, `count` | 次count operationsを指定definite statusにする |
| `storage_commit_unknown` | `runtime`, `ground_truth` | `ground_truth`=`committed`/`not_committed`、caller statusは常にunknown |
| `storage_corrupt` | `runtime`, `scope` | 次open/readで規範corruption status。部分groupをsuccess表示しない |
| `bearer_drop` | `from`, `to`, `count` | 一致する次count accepted copiesをdelivery前にdrop |
| `bearer_duplicate` | `from`, `to`, `copies` | 元を含むcopies件を同一attemptでenqueue |
| `bearer_delay` | `from`, `to`, `delay_ms`, `count` | 一致copyのdue timeへdelayを加算 |
| `bearer_reorder` | `from`, `to`, `group_size`, `order` | groupを集め、0-based permutation順に同時刻enqueue |
| `bearer_corrupt` | `from`, `to`, `field`, `count` | named fieldを決定的に1-bit変更しbinding digestは維持 |
| `partition` | `from`, `to`, `state` | direction別`closed`/`open`。reverse directionは別action |
| `bearer_status` | `from`, `status`, `count` | 次sendをbusy/denied/unavailable等のdefinite resultにする |
| `clock_jump` | `runtime`, `direction`, `delta_ms` | `forward`はruntime clock offsetを加算、`rollback`はschedulerを戻さずnew epoch + uncertainへ変更 |
| `clock_trust` | `runtime`, `state` | `trusted`/`lost`。trustedへ戻す場合は`epoch_id`必須 |
| `entropy_fail` | `stream_id`, `count` | 次count fill callsを失敗させる |
| `permit_deny` | `runtime`, `count`, `reason` | 次count acquire callsをfail closed denialにする |
| `origin_auth_status` | `runtime`, `status`, `count` | 次count evaluate callsを`temporary_failure`/`permanent_failure`にする |
| `availability` | `runtime`, `state` | receiverを`up`/`sleeping`/`unavailable`へ変える |

`storage_status.operation`は`open|begin|get|put|erase|iter_open|iter_next|capacity|commit|rollback`のいずれかです。`status`は`no_space|io_error|corrupt|busy|unsupported_schema`だけで、commit unknownは専用actionを使用します。`bearer_status.status`は`would_block|unavailable|denied|lost_unknown|corrupt`です。

`bearer_corrupt.field`は`transaction_id|attempt_id|event_id|source.local_identity.membership_epoch|target.membership_epoch|service.descriptor_digest|content_digest|deadline_clock_epoch_id|evidence_time.clock_epoch_id|payload`です。ID/digest/payloadは先頭byteを`xor 0x01`、epoch integerはu64値を`xor 1`します。Empty payload指定はscenario errorです。Mutation後も元のbinding/content digestを再計算しません。

`count`は1以上、`copies`は1〜Foundation bearer entry limit、delay/deltaの加算はoverflow検査必須です。`clock_jump.direction`は`forward`または`rollback`だけで、rollback時も`sim_time_ms`は減少しません。複数のbearer actionが同じcopyへ一致した場合、script index順に各actionを適用します。drop後のactionはno-opとしてtraceへ残します。`bearer_reorder`のgroupがscenario終了時に満たない場合はsuccessにせず`INCOMPLETE_REORDER_GROUP`です。

## Deterministic simulator harness

### Ownership

Harnessが所有するもの:

- 1つのvirtual clock
- runtime IDごとのport providerとRuntime instance generation
- global scheduled-event priority queue
- deterministic entropy stream state
- virtual bearer queuesとpartition/availability state
- fault scriptのoccurrence/fire state
- persistent store imageとapplication fixture store
- bounded trace

Runtimeはharnessを知りません。Harnessはapplication admission、Receipt判定、Outcome生成を代行しません。

### Global event order

全scheduled eventは次のkeyで一意にorderします。

```text
(due_time_ms, insertion_ordinal)
```

- `insertion_ordinal`はunsigned 64-bitで0から始まり、event enqueue時に1ずつ増えます。
- 同じ時刻は先にenqueueされたeventが先です。host thread、pointer、map/hash iteration、runtime role priorityをtie-breakへ使用しません。
- ordinal overflowはscenario failureです。
- scenario初期化は、(1) manifest/script validationとhook install、(2) harness runtime nameのASCII byte orderでprovider/Runtime create、(3) time-trigger actionをscript index順でenqueue、(4) create中に要求された初回wakeをruntime name順でenqueue、の順です。これによりtime=0 actionは最初のruntime stepより先です。
- runtime内部で同じlogical timeに複数inputが成立した場合、13章のinput priorityとdurable ingress sequenceを使用します。Harness ordinalで13章のpriorityを上書きしません。

### Event loop

Harnessは次を繰り返します。

1. queueから最小keyのeventを1件popする。
2. `sim_time_ms`をeventの`due_time_ms`へ進める。
3. canceled generationならno-op traceを記録する。
4. それ以外はeventを1件だけ実行する。
5. 生成されたeventへ、その生成順で新しいordinalを割り当てる。
6. public invariantを検査し、trace recordを追加する。

実clock待ち、sleep、host polling intervalを結果へ混ぜません。queue empty、明示stop condition、invariant failure、`max_events`到達のいずれかで停止します。`max_events`到達時に成功扱いせず`SIMULATION_LIVELOCK`です。

### Runtime wakeとstep budget

- runtimeごとに同じdue timeの有効wakeは最大1つです。重複wake requestはcoalesceします。
- より早いwakeへ更新した場合、旧eventをgeneration tokenでcancelし、新eventをenqueueします。
- 1 wakeは`ninlil_runtime_step()`を1回だけ、scenario manifestの固定budgetで呼びます。Defaultは`max_ingress_messages=64 / max_callbacks=64 / max_state_transitions=64 / max_bearer_sends=64`です。Runtime configの対応上限も各64です。
- budget fieldの0はそのcategoryのworkを0件にする明示値です。Non-zeroは対応config以下でなければAPI `NINLIL_E_INVALID_ARGUMENT`で、silent clampしません。
- Step resultの6 work counterはcall開始時に0とし、`runtime_step`外のsubmit/management/query workを含めません。

| Counter | Exact unit / increment point |
| --- | --- |
| `ingress_processed` | Bearer `receive_next`が返したnon-EMPTY messageをCoreがconsumeし、`release_received`した直後に1。Valid/duplicate/invalid/drop/copy/capacity failureを含み、EMPTY/Port errorは0 |
| `callbacks_invoked` | `on_delivery` / `on_reconcile`へactual function entryする直前に1。Callback前commit failureは0 |
| `state_transitions` | `runtime_step`が開始した1 Storage FULL transactionがCore-owned durable bytes/stateを1つ以上変更し、commit OKを観測した直後に1。Multi-record groupも1、read/no-op/rollback/definite failure/COMMIT_UNKNOWNは0 |
| `bearer_sends` | Bearer `send` actual invocationのPort return直後に1。全send statusを同じ1とし、TxGate denial/send前failureは0 |
| `transactions_terminalized` | authoritative projectionがこのstepでnon-terminalからterminalへ初めて変化したtransactionを、対応FULL commit OK後に1 |
| `events_parked` | EventFactがこのstepでnon-PARKEDからPARKED_RETRYへ初めて変化したeventを、対応FULL commit OK後に1 |

`transactions_terminalized` / `events_parked`はbudget categoryでなく`state_transitions`の分類です。同じcommitでstate transition 1と分類 1を返せますが、既存terminal/parked、replay、recovery readを重複加算しません。COMMIT_UNKNOWNのhidden truthがappliedでも当該stepは0で、later recovery readから過去counterを再構成しません。

External side effect前に次のworst-case budgetをcategory別checked sumでreserveします。Reservation自体はcounter 0で、不要と判明した分は同じstepへ返します。

| Scheduler micro-operation | Required remaining budget before start |
| --- | --- |
| receive one ingress | ingress 1 + state transition 1。Durable ingressを保証できないなら`receive_next`を呼ばず、EMPTY/invalidでcommit不要ならstate reservationを返す |
| timer/reducer/recovery/cleanup durable mutation | state transition 1 |
| `on_delivery` dispatch | callback 1 + state transitions 2。Callback前 DELIVERY_STARTEDとCOMPLETE/FATAL/contract-result。DEFERなら2つ目を返す |
| `on_reconcile` dispatch | callback 1 + state transition 1。Known/result/recovery actionの最大1 FULL group |
| ordinary Bearer send | bearer send 1 + state transition 1。Send outcomeのdurable observation headroom |
| remote cancel request send | bearer send 1 + state transitions 2。Pre-send gate close + post-return observation/definite-WOULD_BLOCK reopen |

1 logical operationが残budgetを超える場合はPort/callback/storage side effect 0で次stepへ残し、`more_work=1`です。Durable boundaryで分割可能なattempt prepare→later send、result commit→later reply sendは別micro-operationとして各boundaryでpreflightします。Callback return resultをvolatileに次stepへ持ち越しません。
- `more_work == 1`ならcurrent timeへ新しいwakeをenqueueします。loop内で無制限にstepを再呼出しません。
- `has_next_wake == 1`なら`next_wake_clock_epoch_id`と`next_wake_at_ms`を、現在のtrusted clock epochと一致する最早のfuture absolute pointとしてruntime generation付きeventへupsertします。relative delayへ変換しません。
- 両flagが1ならfuture wakeも登録しますが、current-time wakeのdue keyが小さいため必ず先にstepします。直後のstep resultでfuture pointが変化または消失した場合、旧future eventをgeneration tokenでcancelしてupsert/eraseします。
- `has_next_wake == 0`ならepoch/timeはともにzeroで、Runtimeが以前返した未実行future wakeをcancelします。Bearer delivery等のexternal eventはcancelしません。
- bearer delivery、timer、restart、script actionがruntime ingressを作った場合、そのevent処理後にcurrent time wakeをrequestします。

Step budget vectors:

| Vector | Budget | Required result |
| --- | --- | --- |
| `B1_ALL_ZERO` | 0/0/0/0、pending workあり | `NINLIL_OK`、6 result counters=0、`more_work=1`、state不変 |
| `B2_EXACT_LIMIT` | 64/64/64/64 | 各categoryは実work数と64の小さい方。各counter<=64 |
| `B3_EXCEEDED` | ingress=65、他64 | `NINLIL_E_INVALID_ARGUMENT`、work 0。64へclampしない |
| `B4_ATOMIC_REMAINDER` | state transition残1だが次operationに2必要 | operationを部分実行せずcounter/state不変、`more_work=1` |
| `B5_INGRESS_UNIT` | non-EMPTYをvalid/duplicate/invalid/drop/copy-fail/capacity-failで各1件、別callでEMPTY/Port error | 前6 caseはrelease後`ingress_processed=1`、EMPTY/errorは0。Commit OKしたcaseだけ`state_transitions=1` |
| `B6_DELIVERY_PREFLIGHT` | budget callback1/state2でCOMPLETE、同条件でDEFER、callback1/state1不足、callback前commit failure | COMPLETE=callback1/state2、DEFER=callback1/state1、不足=全0/more1、precommit failure=callback0/state0 |
| `B7_RECONCILE_PREFLIGHT` | callback1/state1でKNOWN_RESULT、callback1/state0 | success=callback1/state1。不足=callback/storage side effect 0、more1 |
| `B8_ORDINARY_SEND_UNIT` | send1/state1で各Bearer status、send1/state0、TxGate OK/TEMP/DENIED/contract fence | actual send caseは`bearer_sends=1`、observation+cursor commit OKならstate1。不足は全0/more1。TxGate non-OKはBearer send0、reducer state+cursor commitでstate1 |
| `B9_CANCEL_SEND_PREFLIGHT` | remote cancelをsend1/state2、send1/state1で各実行 | 前者だけgate-close commit→send1→observation/reopen commitを許し、最大state2。後者はgate close/send/storage write全0、more1 |
| `B10_CLASSIFICATION_FIRST_ONLY` | 1 transaction terminal transitionをreplay、1 Event park transitionをreplay | 初回は各state1 + terminalized1 / parked1。Replay/既存stateは全分類0 |
| `B11_COMMIT_UNKNOWN_COUNTERS` | hidden committed/not-committedのFULL commitをCOMMIT_UNKNOWNで返し、restart read | 当該step state/terminalized/parked=0。Recovery readだけで過去値を加算せず、新しいrecovery commitだけをそのstepのstate transitionとして数える |
| `B12_DURABLE_SPLIT` | attempt prepare可能だがsend budget0、result commit可能だがreply send budget0 | prepare/resultの各FULL commitはstate1で終了可。Sendは0で次stepへ残り、既commit boundaryをrollback/二重計上しない |
| `B13_APPLICATION_SEND_CRASH` | attempt prepared後、Bearer前、return直後、before/after observation hook、observation COMMIT_UNKNOWN両truthでcrash | Before actual sendはsame attemptを後送。Send後/observation未commitはsame ID/bytesだけfresh permitで再送可。Commit済みなら追加send0、unknown解決前send0。New entropy/attempt budget0、receiver callback/effect最大1 |

All-zero budgetをmanifestの継続defaultにするとsame-time wakeが`max_events`まで続くため、B1 testは1 call後にbudgetを変更します。Harnessがこれをsuccess/quiescentへ変換してはなりません。

Scheduler/clock/error vectors:

| Vector | Setup | Required trace/result |
| --- | --- | --- |
| `SCH1_STABLE_RING` | 3 origin transactions、2 inbound deliveries、同時刻Receipt/deadline/callback/dispatch/reverse/custody/cleanupをmap insertion順4種で作り、全22 work kindとcandidate absence sentinelを到達 | 12章owner sequence、chronological/same-time candidate tupleだけで全4 trace digest一致。100-byte target、priority/class/kind/tie exact。Pointer/hash/role/revision/epoch-byte順0 |
| `SCH2_BUDGET_FAIRNESS` | sequence最小ownerを連続readyとし、処理ごとにrecord revision増加かwork kind変更を100回発生。他5 ownerを各class ready、category budgetを交互に1/0 | Step-entry circular passで同owner再選択0。Fitしないcandidateをskipし、規定のcursor-containing commit成功時だけvisited owner sequenceへcursor進行。Bounded steps内に全fit ownerを処理し、continuous mutation/low sequence starvation 0 |
| `SCH3_CURSOR_RESTART` | ring中央でbudget終了/crash/recreate、cursor ownerをcleanupで削除、ring phase中にnew owner作成 | Persist uint64 cursorのupper-boundから再開し1回wrap。New ownerは次step、二重micro-operation/先頭reset0。Owner state/cursor commit unknownはall-or-none |
| `SCH4_OWNER_SEQUENCE_EXHAUSTION` | owner counter 0→1、restart、MAX-1→MAX、MAXでexact retry/new submit/known Receipt/new APPLICATIONを個別実行 | New rootだけCOUNTER_EXHAUSTED/no-reply。Existing-owner retry/Receiptは継続。New submitはprovider/entropy/reservation0。Counter/owner/root record all-or-none、reuse/wrap/zero0 |
| `SCH5_RING_INGRESS_LANES` | continuous provider queue、既存owner 3件、ingress budget/state budget 0/1/N、EMPTY/temp/errorを組合せ | recovery barrier→state poll→fixed cut→ring1/ingress1交互。Ringを先に試し既存owner starvation0。Copyはnext step候補、budget exhaustion後extra receive0 |
| `SCH6_OWNER_BINDING_AND_PRIORITY` | 同一transactionのReceipt/Disposition/CancelResult/duplicate APPLICATIONをcopyし、earlier deadline/later cancel、same-time Receipt/deadlineを作る | Known ingressはexisting owner、新owner counter0。Earlier logical timeが先、same-timeだけ13 priority。Receiptとdeadlineがtemporary owner分離で逆転しない |
| `SCH7_CURSOR_COMMIT_PLACEMENT` | 12章表の全multi-commit kindをcursor commit前後でcrash/unknown | Cursor update exactly1。On-deliveryはtoken claim、cancelはpre-send gate、ordinary/reverseはobservation、reconcileはresult。Group外commitと全体を誤ってall-or-noneにしない |
| `SC1_STEP_CLOCK_ORDER` | recovery、2 callbacks、2 sends、timer、availability、queued ingressを1 stepへ置く | validation→entry clock1→recovery barrier→bearer.state1→fixed cut→ring/ingress lanes。各delivery直前fresh clock1、各TxGate直前fresh clock1、RETRY_LATER後fresh clock1。追加/省略/order差0 |
| `SC2_FRESH_CLOCK_FAILURE` | 2番目fresh callをfailure/UNCERTAIN/epoch changeにする | それ以前のcommit/counter保持、対象effect0、later work0、first error return、more_work1、wake zero、health fixed priority |
| `SE1_FIRST_ERROR_STOPS` | Storage error、later Bearer/callback/別errorを同stepへscriptし順を入替 | Schedulerが最初に観測したnon-semantic errorだけreturn。Later call0、processed counters保持、pending work more_work1、wake zero |
| `AVP1_STATE_POLL` | recovery clear後、exact same tuple、same epoch/different flag、new available epoch、new unavailable epoch、old epoch、budget0、全state status/output shape | Recovery barrier後にstate exactly1。Valid strictly larger epochだけnamespace observation commit、ordered-input/owner sequence0。New unavailableもcommitしてstale availableを消す。Same-epoch flag conflictはDEGRADED/state不変/resume0。Budget0は後続lane0/more1、available0はresume0。Provider wake coalesce後も次step pollで取得 |
| `INQ1_ORDERED_SEQUENCE` | ingress/managementを交互にcommit、restart、commit unknown両truth、counter=MAX | First sequence1、namespace-global strict order、copy/mutation/owner attachとatomic、restart不変。MAXではreceive_next0、management DEGRADED、wrap0 |
| `INQ2_COPY_OWNERSHIP` | ingress copy commit OK/definite failure/unknown/capacity block、各message kind | 全caseでprovider release exactly1。OKだけdurable reduce、failure/unknown/blockでfalse ACK/reply/callback0。Unknown reopenはcopy+sequence all-or-none |

### Metrics and Runtime health vectors

MetricsはRuntime create stage 9からdestroy fenceまでのepoch-local observabilityです。各createはfreshly drawn non-zero metrics epoch、全counter 0で始まり、旧journalからcounterを再構成しません。Metrics epochのstrict uniquenessは保証せず、Runtime/start sampleと一緒に識別します。Exact increment matrixは次です。

| Metrics field | Exact increment trigger |
| --- | --- |
| `submission_calls` | Valid service handle、outer Submission/result pointer+ABI header、owner/re-entry validationを通過したsubmit invocation。以後のnested/content/provider/Storage errorも1。NULL/stale handle、wrong thread/re-entry、outer ABI mismatchは0 |
| `admitted_ready` / `already_admitted` / `rejected` / `idempotency_conflicts` | Public returnがOKかつ対応exact kindの時、該当1つだけ1。API error/COMMIT_UNKNOWNは0 |
| `transactions_satisfied` / `transactions_expired` / `transactions_failed_definitive` / `transactions_outcome_unknown` | このmetrics epochでnon-terminalから対応Outcomeへ初めて移るFULL commit OK。CANCELLED_BEFORE_EFFECT、existing terminal load/replayは0 |
| `events_parked` | non-PARKED→PARKEDのFULL commit OK |
| `events_resumed` | PARKED→READYのavailability resume、または初回explicit RESUMED commit。Replayは0 |
| `events_discarded` | 初回DISCARDED audit/tombstone FULL commit OK。ALREADY replayは0 |
| `late_evidence` | terminal後に新しいvalid late-evidence materialをraw insertまたはsummary updateへdurably commit。Exact duplicateは0 |
| `duplicate_logical_delivery` | valid duplicate APPLICATIONをdurable identity/bindingで認識し、new callbackを抑止したmessage |
| `application_callback_invocations` | `on_delivery` actual function entry直前 |
| `reconcile_invocations` | `on_reconcile` actual function entry直前 |
| `delivery_token_timeouts` | active token→expired/RECOVERY_REQUIRED FULL commit OK。Late completion/replayは0 |
| `storage_failures` | Published RuntimeのStorage Port callがBUSY、NO_SPACE、IO_ERROR、CORRUPT、COMMIT_UNKNOWN、UNSUPPORTED_SCHEMA、unexpected NOT_FOUND/BUFFER_TOO_SMALLを返した各回。Expected miss/end/size probe、create publish前/destroy fence後は0 |
| `bearer_would_block` | Published Runtimeのactual Bearer sendがWOULD_BLOCKを返した各回。同じcancel attemptのpermitted reinvocationも各1 |

全counterは該当観測/FULL commit OK直後にchecked incrementし、`UINT64_MAX`でsaturateしてwrapしません。Saturationはhealth/reducerを変更しません。`metrics_snapshot`は全fieldを1つのowner-thread logical snapshotで返し、自身をcountしません。

| Vector | Trace | Required metrics result |
| --- | --- | --- |
| `MT1_EPOCH_RESTART` | create、複数operation、destroy/recreate、後でclock epoch変更 | createごとにnew metrics epoch/all counter 0。Start clock epoch/timeは各create sampleへ固定し、旧counter再構成と後変更0 |
| `MT2_SUBMISSION_BOUNDARY` | outer validation前の各error、通過後のnested/content/provider/Storage error、4 semantic kind、COMMIT_UNKNOWN | outer前はsubmission_calls 0、通過後は各1。Semantic OKだけ対応kindをexactly 1、API error/unknownはkind 0 |
| `MT3_OUTCOME_FIRST_COMMIT` | 4 counted Outcome、CANCELLED_BEFORE_EFFECT、同terminal replay/restart load | 4 Outcomeは初回FULL commitだけ各counter1。Cancel/replay/loadは全4 counter 0 |
| `MT4_EVENT_EVIDENCE_DEDUP` | park→availability resume→park→explicit resume→discard、各replay、unique/duplicate late evidence、duplicate APPLICATION、active exact duplicate Receipt storm | 初回/new material commitだけ対応counterを1。Replay/duplicate evidenceはlate metric0・spool revision不変、duplicate APPLICATIONはcallback0かつduplicate counter1。Duplicate stormだけでCOUNTER_EXHAUSTEDへ進まない |
| `MT5_CALLBACK_TOKEN` | delivery/reconcile actual entry、callback前commit failure、token timeout、late completion | actual entryだけcallback種別counter1。Precommit failure 0。Timeout FULL commitだけtoken timeout1 |
| `MT6_PORT_FAILURES` | published前/後/fence後の全listed Storage status、expected miss/end/probe、Bearer WOULD_BLOCKとTxGate denial | published Runtimeのlisted unexpected Storage returnだけcallごとに1。Expected/create/destroyは0。Actual Bearer WOULD_BLOCKだけ1、TxGate denialは0 |
| `MT7_SATURATION_SNAPSHOT` | test seamで各counterをMAX-1にしtriggerを2回、snapshotを2回 | 最初でMAX、次もMAX、health/state不変。2 snapshotsはbyte/value同値でcounterを増やさない |

Runtime healthはactive degraded-cause multisetから導出し、発生順にstickyにはしません。Cause 0ならOK/NONE、1件以上なら次のfixed priorityで最上位reasonを返します。

| Priority | Active cause / public reason | Exact clear boundary |
| ---: | --- | --- |
| 1 | Storage corrupt/definite I/O / `NINLIL_REASON_STORAGE_IO` | successful reopen + schema/capacity/recovery scan完了 |
| 2 | unresolved commit unknown / `NINLIL_REASON_STORAGE_COMMIT_UNKNOWN` | authoritative record resolution |
| 3 | callback/known-result contract fence / `NINLIL_REASON_CALLBACK_CONTRACT` | 該当deliveryのvalid reconcile terminal commit |
| 4 | callback FATAL/application failure fence、Bearer receive/state denial / `NINLIL_REASON_APPLICATION_FAILED` | Durable markerまたは12章instance source-key tableのexact clear |
| 5 | origin provider permanent/invalid / `NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE` | 後のvalid provider evaluation。Temporary failureはcauseをaddしない |
| 6 | unsafe clock/epoch fence / `NINLIL_REASON_CLOCK_UNCERTAIN` | trusted non-regressing sample + 全affected timer/token guard再評価 |
| 7 | non-recoverable counter headroom / `NINLIL_REASON_COUNTER_EXHAUSTED` | 同Runtime instanceではclearしない |
| 8 | entropy exhaustion、Bearer/TxGate method fault、internal invariant / `NINLIL_REASON_OUTCOME_UNKNOWN` | 12章distinct source-key table。Internal invariantは同Runtime instanceでclearしない |

| Vector | Cause trace | Required health result |
| --- | --- | --- |
| `HL1_FIXED_PRIORITY` | priority 8→6→3→5→1を順にaddし、逆順variantも実行 | 発生順に依存せず常にactive中の最小priority reason。HEALTH_FATAL生成0 |
| `HL2_CLEAR_AND_REFCOUNT` | 同priority causeを別deliveryで2件addし1件ずつclear、higher causeもclear | 1件残る間reason維持。Higher clear後は次active reason、最後のcause clear後だけOK/NONE |
| `HL3_PROVIDER_HEALTH` | provider temporary、permanent、invalid、valid evaluation | temporaryはWOULD_BLOCK/health不変。Permanent/invalidはDEGRADED/GRANT_PROVIDER_UNAVAILABLE、valid evaluation後clear |
| `HL4_NON_CAUSES` | API invalid、normal rejection、Bearer WOULD_BLOCK、business transaction OUTCOME_UNKNOWNだけを生成 | Runtime healthはOK/NONEのまま。Business outcomeをpriority 8 internal fenceと混同しない |
| `HL5_NONCLEARING_CAUSES` | counter exhaustion、internal invariantをaddし、同じRuntimeで通常のsuccessful operationを複数実行 | 同Runtime instanceでclearせず、理由をNONEや低priorityへsilent変更しない |
| `HL6_RESTART_RECONSTRUCTION` | callback contract/FATAL RECOVERY_REQUIRED各2件、counter marker、instance-local entropy/Bearer causeを作りdestroy/crash→recreate | Durable markerだけをreference-count再構成しStage 9直後からDEGRADED exact priority。Metricsはzero。Instance-local causeはcopyせずnew observationで再評価。Reconcile marker clearごとに1 reference clear |
| `HL7_PRIORITY8_SOURCE_LATCHES` | transaction entropy failure反復、attempt entropy failure、TxGate fault、send/receive/state fault反復を別々にaddし、各methodを順に正常化 | 反復はsourceごと1 reference。Transaction成功はattemptをclearせず、valid TxGate/send/receive/stateは同methodだけclear。最後でOK/NONE。Restartはinstance key 0、durable invariantだけ再構成 |
| `BS7_DENIED_HEALTH_LIFECYCLE` | receive/state DENIEDを各反復、normal method return、callback durable marker併存、CORRUPT→DENIED、restart | DENIED keyはmethodごと1 reference。Normal returnは同methodだけclear。CORRUPT faultはDENIEDでclear後denial key add。Bearer keys clear後もcallback markerが残ればDEGRADED、restartはBearer key 0 |

Next-wake vectorsはshared clock epoch=`a000...0001`でt=100から開始します。

| Vector | Step result / setup | Required harness behavior |
| --- | --- | --- |
| `W1_IMMEDIATE_ONLY` | more_work=1、has_next_wake=0、epoch/time zero | t=100へ1 wakeをenqueueし、clockを進めない |
| `W2_EARLIEST_FUTURE` | pending timer=180, 220、more_work=0、has_next_wake=1、epoch=`a000...0001`、at=180 | t=180だけをRuntime future wakeとしてenqueueする。t=150に外部wakeされてもtimerを早期発火せず、再び180を返す |
| `W3_BOTH` | more_work=1、has_next_wake=1、epoch=`a000...0001`、at=250 | t=100とt=250を登録し、t=100を先に1 stepだけ実行する。次resultの最早futureが200なら250をcancelし200へ置換する |
| `W4_QUIESCENT` | more_work=0、has_next_wake=0、epoch/time zero | Runtime由来wakeなし。queueにexternal eventもなければscenarioはquiescent |
| `W5_INVALID_SHAPE` | has_next_wake=0でepoch/time non-zero、または1でepoch zero/at<=100 | harness contract failure。時刻を補完、clamp、推測しない |
| `W6_EPOCH_LOST` | old epochのfuture wakeあり、その後clock uncertainまたはepoch=`a000...0002`へ変更 | old wakeをcancel/no-op化しcurrent-time clock-state wakeを行う。Runtimeはhas_next_wake=0、epoch/time zero、health/reasonに`CLOCK_UNCERTAIN`を返し、異なるepochの数値を比較しない |

Future wake eventをpopした時点でもeventへ保存したepochとcurrent clock epochをexact比較します。不一致/uncertainならtimer dueとみなさずclock-state inputとしてRuntimeをwakeし、同じabsolute numberをnew epochへ移植しません。Due-now timerは`has_next_wake`ではなく`more_work`へ現れます。

Retention vectors:

| Vector | Setup | Required result |
| --- | --- | --- |
| `RET1_EXCLUSIVE_END` | terminal/result/observationをt=100、duration=10/10/0でcommitし、t=100/109/110をstep | Observationはseparate cleanupでt=100からeligible、他は109まで保持、110 exactでatomic cleanup。早期query/cache miss 0 |
| `RET2_PENDING_CLOCK` | retention-starting business commit時Clock uncertain、後にepoch A/t=500 trusted | Business stateはcommit、basis pending/cleanup wake0。t=500からfull durationをFULL設定後だけwake/cleanup |
| `RET3_EPOCH_REBASE` | epoch A/delete=1000を保持中、epoch B/t=20へchange | A数値と比較せずB/t=20+full durationへ延長。Rebase commit失敗/unknownでdelete0、record保持 |
| `RET4_OVERFLOW` | trusted now=UINT64_MAX-5、duration=10 | overflow flag、delete/wake0、record保持、health COUNTER_EXHAUSTED。Wrap/即時cleanup0 |
| `RET5_ATOMIC_RELEASE` | terminal transactionにmapping/evidence/quota/resource、result cache、blocked flagを持たせcleanup | 対象retention groupごと1 FULL commit、partial delete0。Capacity improvementが該当すれば同commitでepoch+1/blocked clear |
| `RET6_ATTEMPT_INDEX_BOUNDARY` | Application/cancel attemptを生成しterminal化、retention end前/at end、cleanup COMMIT_UNKNOWN両truth、同じscripted candidateを再draw | Terminal前/retention中/cleanup OK前はcollision。Unused cancel reservationとremote echoはindex 0。Cleanupはparent/全attempt index all-or-none、OK後だけsame 128-bit candidate再利用可。Unknown解決前はfence、orphan/early reuse/double delete 0 |

### Crashとrestart

`crash_runtime`は`ninlil_runtime_destroy()`やapplication shutdown callbackを呼びません。

- Runtime object、volatile queue、open transaction、iterator、active delivery-token registry、application volatile stateを失います。
- crash前にcopyされたdeferred tokenをnew Runtime instanceでactiveへ戻しません。Recoveryはdurable deliveryを`RECOVERY_REQUIRED`へ収束し、旧tokenのlate completionをretention中`NINLIL_E_INVALID_STATE`にします。
- pending runtime wakeはinstance generation不一致によりcancelされます。
- committed storage、application fixtureのdurable store、virtual clock、entropy counter、fault occurrence、script fire state、bearerが既にownershipを受理したcopyは保持します。
- active uncommitted storage transactionはbackendのcrash recovery規則によりall-or-noneへ収束します。
- accepted済みbearer copyはsource crash後もdeliveryできます。これによりattemptは`delivery possible`です。
- targetがdownの時刻にdueとなったcopyはbufferせず`RECEIVER_UNAVAILABLE` observationにします。Core retryが新attemptを作ります。
- automatic restartは`crash_time + restart_after_ms`へscheduleします。値省略時はoperator/scriptがrestartするまでdownです。
- restartは同じruntime ID、role、fixture identity、store identity、port configで新instance generationを作ります。
- external input/timerより先に13章の`RECOVERY_FENCE`を完了します。
- transaction/event IDとattempt budgetはdurable stateから復元します。ATTEMPT_PREPAREDにsend observationがなければsame attempt ID/bytesをfresh permitでreinvokeし、observation後のlogical retryだけnew attempt IDです。
- EventFact `PARKED_RETRY`はrestartだけで再開せず、fresh Bearer availability epoch + `available=1`または一意なresume operationを必要とします。

### Bearer availability epoch and Runtime capacity epochs

Bearerごとの`availability_epoch`はunsigned 64-bitで、0をunknown、1以上を有効値とします。

- availableの0↔1変化は必ずstrictly larger epochを発行します。さらにpartition open、queue fullからwatermark未満、bearer reopen等、available=1のまま実際に利用可能性を改善したtransitionもstrictly larger epochを発行できます。
- polling、available bitもblocked-work成功可能性も同じstateの再設定、Runtime restartだけではepochを増やしません。同じepoch/different availableはcontract failureです。
- EventFactはdurable `last_consumed_availability_epoch`より大きいepochを初めてcommitしたときだけ新retry cycleへ進めます。
- 同じepochをduplicate deliveryしてもcycleを複数回resetしません。
- explicit resumeはcaller-supplied operation IDとexpected spool revisionをdurable commitし、同じoperation IDの再送をidempotent no-opにします。
- M1aの`ninlil_event_discard()`はactor、reason、event ID、payload digest、未達evidence、時刻を1つの`FULL` audit transactionへcommitした後だけpayloadを解放します。commit failure/unknown時はspoolを保持します。

Vector `AV1_BEARER_IMPROVEMENT_ONCE`はEventFactをBearer WOULD_BLOCKによりPARKED_RETRY、last seen/consumed availability epoch=1にします。Poll、exact same-state notification、successful send、Runtime restartはepoch=1のままです。Providerはdegradeでepoch=2/available=0を発行し、Runtimeはnamespace tupleをFULL commitしてresume 0、その後queue/path改善でepoch=3/available=1を発行します。Runtimeはcompleted summary/new cycle/attempt count 0/last seen+consumed=3/spool revisionを1つの`FULL` commitへまとめます。Exact tuple/古いepochを10回通知しても追加cycleは0です。Same epoch=3/available=0はcontract failureでnamespaceをavailable=1から書き換えずDEGRADED/resume 0です。Runtime resource capacity epoch=4を通知/代入してもavailability inputにならず、stale reasonへ写像しません。Bearer counter overflowはwrapせずprovider/CoreをDEGRADEDにし、new cycle/sendを0にします。Reason value 77の旧名称はtest sourceを含め出現0件でなければなりません。

Vector `AV2_MULTI_EVENT_FANOUT`はowner sequenceの異なるeligible PARKED Event 6件、APPLICATION_REMEDIATION 1件、active 1件をepoch=1で用意し、new available epoch=2をstate pollで観測します。Namespace observationは1 FULL/state transition、Event一括write0です。以後owner ring順にeligible Eventだけ1件=1 FULLでresumeし、budget/crash/cursor commit unknownを跨いでも各Eventがepoch2を最大1回consumeします。途中でepoch3を観測した場合、未consume Eventはlatest 3を1回だけ、既にREADYは追加cycle0です。Application-remediation/activeはfan-out0で、activeが後でparkするcommitはlatest epochをseenへsnapshotします。

### Runtime resource-limit validation vectors

`ninlil_resource_limits_t`は全fieldをcallerが明示し、0をdefault、unbounded、disabledへ読み替えません。次表は`NINLIL-FOUNDATION-SMALL-1`のinclusive accepted setです。

| Field | Controller accepted | Endpoint accepted |
| --- | --- | --- |
| `max_services` | 1..16 | 1..8 |
| `max_nonterminal_transactions` | 1..256 | 1..32 |
| `max_targets_per_transaction` | exactly 1 | exactly 1 |
| `max_logical_payload_bytes` | 1..1,024 | 1..1,024 |
| `max_durable_outbox_payload_bytes` | 1..262,144 | exactly 0 |
| `max_attempts_per_target_per_cycle` | exactly 8 | exactly 8 |
| `max_cancel_attempts_per_transaction` | exactly 1 | exactly 1 |
| `max_evidence_per_target` | 1..8 | 1..8 |
| `max_retained_terminal_transactions` | 1..2,048 | 1..64 |
| `max_nonterminal_deliveries` | 1..32 | 1..32 |
| `max_event_spool_count` | exactly 0 | 0..32 |
| `max_event_spool_bytes` | exactly 0 | count=0ならexactly 0、count>0なら2,560..32,768 |
| `max_result_cache_entries` | 1..64 | 1..64 |
| `max_retained_dispositions` | 1..64 | 1..64 |
| `max_ingress_per_step` | 1..64 | 1..64 |
| `max_callbacks_per_step` | 1..64 | 1..64 |
| `max_state_transitions_per_step` | 2..64 | 2..64 |
| `max_bearer_sends_per_step` | 1..64 | 1..64 |
| `max_deferred_tokens` | 1..32 | 1..32 |

全configはさらに`max_deferred_tokens <= max_nonterminal_deliveries <= max_nonterminal_transactions`、`max_event_spool_count <= max_nonterminal_transactions`を満たします。Controllerは`max_durable_outbox_payload_bytes >= max_logical_payload_bytes`です。比較、`N = max_nonterminal_transactions + max_retained_terminal_transactions`、capacity limit導出の全加算・乗算はcheckedです。

| Vector | Mutation / boundary | Required result |
| --- | --- | --- |
| `RL1_ROLE_MIN_MAX` | 両roleで上表の各fieldを1つずつinclusive min/maxへし、他fieldはcross-fieldを満たす値 | 全case create成功。0を許すEndpoint outbox、Endpoint event count/bytesのzero pair、Controller event zero pairも成功 |
| `RL2_BELOW_OR_CONDITIONAL` | 各non-zero minを1小さくする、exactly 1を0、attempts 8を7、Endpoint event count=0/bytes>0、count>0/bytes=0または2,559 | `NINLIL_E_INVALID_ARGUMENT`、Runtime NULL、namespace allocation/Storage open 0 |
| `RL3_ABOVE_PROFILE` | 各inclusive maxを1大きくする、exactly 1を2、attempts 8を9、Controller event count/bytesをnon-zero | `NINLIL_E_UNSUPPORTED`、Runtime NULL。Larger profileへsilent昇格しない |
| `RL4_CROSS_FIELD` | deferred>deliveries、deliveries>transactions、event count>transactions、Controller outbox<logical payloadを各1件だけ成立 | `NINLIL_E_INVALID_ARGUMENT`、Runtime NULL、Port call 0 |
| `RL5_ENDPOINT_EVENT_COUPLING` | count=0/bytes=0、count=1/bytes=2,560、count=32/bytes=32,768 | 3件とも成功。bytesはcount件を同時収容する保証でなく、各admissionで残量を再検査 |
| `RL6_DERIVATION_OVERFLOW` | valid ABI configのtransaction/retention/target/evidence fieldへ、checked N/target/evidence limit formulaがoverflowする値を入れてpublic create | profileへclampせず`NINLIL_E_INVALID_ARGUMENT`、Runtime NULL、Allocator/Port/capacity metadata write 0。Arithmetic overflow判定をlarger-profile fallbackへ隠さない |
| `RL7_RETENTION_AND_RESERVED` | terminal=1/max、result=1/terminal、observation=0/maxを境界検査し、範囲外、result>terminal、いずれかのreserved非zeroを個別注入 | valid境界だけ成功。不正は`NINLIL_E_INVALID_ARGUMENT`、Runtime NULL |

`RL2`と`RL3`は同時に複数違反を作らず、下限/conditional違反の`INVALID_ARGUMENT`とnamed profile上限超過の`UNSUPPORTED`を混同しません。各error caseは`*out_runtime`がcall開始時のpoisonからNULL化され、allocator/clock/entropy/Storage/Bearerを一切呼ばないことも検査します。

`max_event_spool_bytes=2,560`は有効ですが、management reservationだけで全量を使うため、payloadが1 byte以上のEventFactを1件もadmitできません。Receive-onlyにするならcount/bytesを0/0、Event送信を使うなら最大payloadと同時保持件数を含む値をprofile authorが明示し、最小値を実用defaultとして提示しません。

Public Runtime capacityの`capacity_epoch`はBearer `availability_epoch`と別domainで、resource kind間でも比較しません。`ninlil_capacity_snapshot()`はkind 1〜11を数値昇順でexactly 11件返し、roleで不使用のkindもzero limit entryとして残します。

Foundation fixtureのlimitは12章`NINLIL-FOUNDATION-SMALL-1`から次のchecked derivationで固定します。`N = max_nonterminal_transactions + max_retained_terminal_transactions`、target/evidence乗算もcheckedです。

| Kind | Unit / limit formula | Controller limit | Endpoint limit |
| --- | --- | ---: | ---: |
| `NINLIL_RESOURCE_SERVICE` | registered service slots / max services | 16 | 8 |
| `NINLIL_RESOURCE_TRANSACTION` | nonterminal + retained terminal lifecycle slots / N | 2,304 | 96 |
| `NINLIL_RESOURCE_TARGET` | concrete target slots / N × max targets | 2,304 | 96 |
| `NINLIL_RESOURCE_OUTBOX_BYTES` | logical retained Command payload bytes / durable outbox byte max | 262,144 | 0 |
| `NINLIL_RESOURCE_DELIVERY` | inbound delivery lifecycle slots / max nonterminal deliveries | 32 | 32 |
| `NINLIL_RESOURCE_EVENT_SPOOL_COUNT` | held EventFact count / max event spool count | 0 | 32 |
| `NINLIL_RESOURCE_EVENT_SPOOL_BYTES` | portable logical EventFact bytes / max event spool bytes | 0 | 32,768 |
| `NINLIL_RESOURCE_RESULT_CACHE` | cached result/disposition/token tombstone / result cache + retained disposition max | 128 | 128 |
| `NINLIL_RESOURCE_EVIDENCE` | evidence slots / N × max targets × (max evidence + 1 summary) | 20,736 | 864 |
| `NINLIL_RESOURCE_INGRESS` | copied, unreduced Bearer messages / max ingress per step | 64 | 64 |
| `NINLIL_RESOURCE_DEFERRED_TOKEN` | active delivery tokens / max deferred tokens | 32 | 32 |

各entryは同じlogical snapshotの`limit/used/reserved/high_water/capacity_epoch`を返します。

- checked `used + reserved <= limit`を常に満たします。`used`はcommit済みlive unit、`reserved`はCore-owned reservation recordで確保済みだが未使用のunitです。物理空きや推定値をreservedにしません。
- `high_water = saturating_max(previous high_water, used + reserved)`で、減少/restartしても下げません。
- capacity metadata、high-water、epoch、blocked flagはstorage namespaceへpersistし、restartでresetしません。Limit変更を同じnamespaceへsilent適用しません。
- 複数kindはkind昇順に全予約し、途中失敗は逆順releaseします。Application effect/callback、admission commit、attempt sendをpartialに始めません。
- Live EventFactのportable `EVENT_SPOOL_BYTES` admission costはchecked `payload.length + NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES`、すなわちexactly `payload.length + 8×256 + 512 = payload.length + 2,560`です。Admission staging中は全totalをreserved、FULL admission後はpayloadだけをused、未使用management slot 2,560をreservedにします。Resume/discard成功は該当fixed slotだけをreservedからusedへ移し、live中は常に`used + reserved = payload.length + 2,560`です。
- Attempt detail、retry/cumulative summary、storage key/index/padding/CRC等のphysical overheadはpublic `EVENT_SPOOL_BYTES`へ含めず、Storage Portの`capacity.max_bytes/used_bytes`で別に管理します。Receipt/discard terminal commitでpayloadとunused management slotを解放し、portable retained bytesはexactly `successful_resume_operation_count × 256 + (discard_operation_committed ? 512 : 0)`です。Dedup retention cleanupで残りも0へ解放します。
- Deferred tokenは48-byte portable token sizeではなくactive token **count**をunitにし、storage/allocator bytesと二重計上しません。
- EVIDENCEはorigin transaction/targetごとにsummary 1 used + raw 8 reservedでadmissionし、new materialごとにraw 1をreserved→usedへ移します。Raw full後はsummary updateだけです。Terminalでもunused rawをreleaseせず、transaction evidence retention cleanupだけで全9 slotsを解放します。

Vector `CAP1_ELEVEN_ORDER`はcreate直後、service登録後、C1/E1 admission後、restart後の各snapshotでentry_count=11、kind昇順、上表limit、全entryのinvariantを検査します。Entry capacity=10では`NINLIL_E_BUFFER_TOO_SMALL`、required count=11、entriesへのpartial write 0です。

Vector `CAP2_RESERVATION_ATOMIC`は3つのkindを必要とするoperationで、1番目/2番目/3番目の各reserveを意図的に失敗させます。失敗後は全entryのused/reservedとdurable operation stateが開始前と一致し、callback/send 0です。成功variantだけがreservedをusedへatomic移行し、`used + reserved`の総量を二重増加させません。

Vector `CAP3_IMPROVEMENT_EPOCH`はEndpoint deferred-token entryから開始します。初期epoch=1、used=32、reserved=0、high_water=32で33件目を`APPLICATION_BUSY`として実際にblockしpersistent blocked flagを立てます。1 tokenのcomplete/timeout invalidationを`FULL` commitするとused=31、availableが増えて同class workを再評価可能になるためepoch=2、blocked clearです。

- poll、同値snapshot、restart、new reservation/使用増ではepoch=2のままです。
- blocked flagなしの別token releaseでもepochを増やしません。
- 再度used+reserved=32でworkをblockし、release/recovery FULL commitした時だけepoch=3です。
- epoch increment overflowはwrapせずhealth DEGRADED / `NINLIL_REASON_COUNTER_EXHAUSTED`です。
- CAP3のRuntime capacity epochをEvent retryのBearer availability epochとしてconsumeしません。Bearer側に実際のavailability improvementがない限りPARKED_RETRYのcycleは不変です。

Vector `CAP4_CORRUPT_LEDGER`はused+reserved>limit、high_water<used+reserved、予約なし消費、underflowを1つずつloadします。Snapshotを正常値へclampせずstorage corruption相当でfail closedし、新admission/callback/sendを0にします。

Vector `CAP5_EVENT_SPOOL_PORTABLE_COST`は他EventのないEndpointで10-byte E1をadmitします。Admission commit前はused=0/reserved=2,570、FULL commit後はused=10/reserved=2,560です。Attempt detailと全retry/cumulative summaryを最大まで生成してもpublic totalは2,570のまま、Storage Port physical `used_bytes`だけが増え得ます。成功resumeを2回使用するとused=522/reserved=2,048、total=2,570のままです。Required Receiptでterminalならpayloadとunused slotを解放してused=512/reserved=0、別variantでその後のparkをdiscardしてterminalならused=1,024/reserved=0です。Dedup retention cleanup後は両方0です。Admission時のavailable bytesが2,569だけのvariantはcapacity rejection、reservation/used/callback/send 0で、physical estimateをpublic costへ足して拒否してはなりません。

Vector `CAP6_LATE_EVIDENCE_RESERVATION`はfixture `L=8`で1 target admission後、EVIDENCE used=1/reserved=8からraw 3件をcommitしてused=4/reserved=5とし、Receipt未達のままCommandをEXPIRED、別variantのEventをdiscard terminalにします。Admission FULLはsummary+L raw cellを最大encoded sizeでphysical materializeし、1 replacement journal headroomをpreallocateします。Terminal commit後も4/5を維持します。他resourceをcapacity exactまで埋めてからlate new materialを5件rawへ、9件目以後をsummaryへcommitでき、Outcome反転0、late metricはnew materialごとに1、exact duplicateは0です。`L=1` variantはadmission used=1/reserved=1、first material後2/0、2件目以後summary updateだけです。Event revision MAX terminal variantでもlate update後MAXを維持します。Evidence retention cleanupだけでused/reserved=0になり、blocked workがあった場合だけcapacity epochを進めます。

Vector `CAP7_SERVICE_INGRESS_DURABLE`はfirst service registry commitとBearer ingress copy/reduceの各境界でSERVICE/INGRESS used/high-waterを検査します。Service recreate attachはused不変、INGRESS copy後crashはused/message/sequenceを復元、reduce/drop commitだけでreleaseします。Restart/step resetによるzero化、callback pointer数のSERVICE計上は0です。

Vector `CAP8_BLOCK_FLAG_FAILURE`は各kindでblocked=0からactual exhaustionを起こし、capacity hook before/after、metadata commit OK/BUSY/NO_SPACE/IO/CORRUPT/COMMIT_UNKNOWNを注入します。OK後だけsemantic rejectionとblocked=1、既blocked repeatはwrite0。BUSY/Storage error/unknownは12章API/result/namespace fenceへ一致し、semantic rejection metric/epoch変化0です。Release variantはblocked clear+epoch incrementを同じhook pair/FULL commitへまとめ、commit unknown両truthをreopenで解決します。

Vector `CAP9_EPOCH_MAX_RELEASE`は各kindを`used>0/reserved>0/blocked=1/capacity_epoch=UINT64_MAX`にし、terminal/cleanup releaseを実行します。Releaseとbusiness stateは進み、used/reservedが規定量だけ減少、blocked=0、epoch MAX、durable COUNTER_EXHAUSTED markerを同じFULL commitへ含めます。Commit unknown両truthはgroup all-or-noneです。以後new workはCOUNTER_EXHAUSTEDですが、existing Receipt/terminal/cleanup/releaseは継続し、wrap/zero/resource leak 0です。

### Event manual-resume ledger vectors

EventFact admissionは`NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS=8`個のresume operation/audit/result slotと、1個のdiscard slotをevent spool logical bytesへpre-reserveします。このreservationをEvent admissionの他recordと同じatomic capacity decisionへ含め、確保不能なら`NINLIL_REASON_CAPACITY_EXHAUSTED`でadmitしません。Terminal後もservice dedup retention終了までslotをsilent eviction/reuseしません。

Vector `M1_RESUME_LEDGER_EIGHT`は同じE1 EventFactをPARKED_RETRYへ戻しながら、operation ID=`f000...0001`〜`f000...0008`、actor=`d000...0001`、reason=`NINLIL_RESUME_TEST`、metadata ASCII `resume-1`〜`resume-8`で8回のdistinct successful resumeを行います。各requestは直前queryのexact spool revisionを使います。

各callは`NINLIL_OK + NINLIL_EVENT_RESUME_RESUMED + NINLIL_REASON_NONE`で、completed cycle summary、新retry cycle、attempt count=0、operation digest/audit/result、checked spool revision incrementを1つの`FULL` transactionへcommitします。Testは各resume間に8-attempt exhaustionを明示して再度PARKED_RETRYへし、通常stepや同じavailability epochだけでparkを解除しません。

8 slot使用後、同じEventをPARKED_RETRYにしてunseen operation ID=`f000...0009`をcurrent expected revisionで呼ぶ`M2_RESUME_NINTH`は、`NINLIL_OK + NINLIL_EVENT_RESUME_LIMIT_EXHAUSTED + NINLIL_REASON_CAPACITY_EXHAUSTED`です。State、retry cycle、attempt count、spool revision、operation ledger、event spool used/reserved bytes、他resource reservationを変更しません。

Operation lookupはcurrent state/revision guardより先です。

- `M3_OLD_REPLAY_AFTER_RELEASE`: M1のoperation 1とexact same request bytesを、後続required ReceiptでEventがRELEASEDになった後にreplayする。Persist済みcycle/revisionを持つ`NINLIL_EVENT_RESUME_ALREADY_RESUMED`を返し、新cycle/spool mutation/resource changeは0です。Current revisionとの不一致でSTALEへ変えません。
- `M4_OLD_ID_DIFFERENT_DIGEST`: operation 1のmetadataを1 byte変更して同じIDを使う。Current stateを問わず`NINLIL_EVENT_RESUME_CONFLICT + NINLIL_REASON_RESUME_CONFLICT`で、state/revision/resource changeは0です。
- `M5_CROSS_KIND_ID`: resume ledgerのIDをdiscard requestへ再利用する、またはdiscard ledger IDをresumeへ再利用する。Operation kind/digest conflictとして対応するCONFLICTを返し、current state/revisionを評価しません。
- `M6_COMMIT_UNKNOWN`: new resume operationのcommit acknowledgementをunknownにする。同じrequestでrestart/retryし、0回またはexactly 1回のcycle/revision mutationとexactly 1 ledger resultへ収束します。
- `M7_REASON_IS_AUDIT_ONLY`: 4 resumable park causeそれぞれに5 known resume reasonを組み合わせた20 variantを実行する。Exact revision/available ledgerなら全てRESUMEDで、reason/cause matching rejectionは0です。
- `M8_COUNTER_NOT_RESUMABLE`: cause=`COUNTER_EXHAUSTED`、unused operation ID、current expected revision、各known resume reasonでcallする。全5 variantが`NINLIL_OK + NINLIL_EVENT_RESUME_NOT_RESUMABLE + NINLIL_REASON_COUNTER_EXHAUSTED`、request operation IDとcurrent cycle/revisionをechoし、state/revision/ledger slot/resource/metrics mutation 0です。Stale revisionや9th limitを評価しません。

M3/M4は8 slot使用後もlookup可能でなければなりません。9th limitを理由に既存operation replay/conflict判定を失わせません。

### Event discard audit vector

Vector `A1_EVENT_DISCARD`はE1をlocal admission直後、attempt前、spool revision=`1`で使用します。

```text
operation ID                         c0000000000000000000000000000001
actor ID                             d0000000000000000000000000000001
expected event ID                    90000000000000000000000000000001
expected content digest              1:c79dfd1639cb01c6e9475beccd17d9e076ca80f62f4c5a505a1586cc7a3e9338
expected spool revision              1
discard reason                       NINLIL_DISCARD_TEST_CLEANUP
acknowledge required Receipt absent  1
audit metadata                       ASCII "fixture-cleanup"
clock sample                         epoch a000...0001, now 2000, TRUSTED
```

Runtimeはaudit clock epoch/time、request binding、highest evidence、retry counters、terminal Outcome/tombstone、payload/spool erase、revision=`2`を同じ`FULL` transactionへcommitします。成功resultは`NINLIL_EVENT_DISCARD_DISCARDED`、audit epoch=`a000...0001`、audit time=`2000`、`spool_released=1`です。Audit epoch/timeのportable semantic sizeは16+8=24 bytesで、durable record全体はstorage entry formulaで数えます。

- commit definite failure/unknownではDISCARDEDを返さずpayloadを保持します。Reopen後は「payloadあり/auditなし」または「payloadなし/audit+tombstoneあり」のどちらかだけです。
- clock sampleがuncertain、epochがoperation中に変化、またはtimestamp加算/取得不能ならAPI `NINLIL_E_CLOCK_UNCERTAIN`、result time fields zero、spool不変です。
- 同時刻のvalid required Receiptを先にcommitした場合、discard resultは`NINLIL_EVENT_DISCARD_ALREADY_RELEASED`、audit epoch/time zero、`spool_released=0`です。

### Management linearization vectors

| Vector | Setup | Required result |
| --- | --- | --- |
| `MG1_CANCEL_DEADLINE_ORDER` | Command effect deadline=100。cancelをtrusted t=100と101で別実行 | t=100はsame-time priorityでcancelが先にFENCED。t=101はdeadline terminal commitが先でcancel recordなしのALREADY_TERMINAL。Bearer drain/send/callback 0 |
| `MG2_EVENT_TIMEOUT_RESUME` | Event 8th attempt timeout=100、まだstep未処理。unseen resumeをtrusted t=100と200、request expected revisionをtimeout前/後の各値で実行 | 両timeでtimeoutを先にPARKEDへcommit。同時刻priority 7→8、overdue chronological orderを照合。Old expectedはSTALE、post-timeout authoritative revision一致だけRESUMED |
| `MG3_DISCARD_RECEIPT_ORDER` | already durable required Receiptをdiscardより前/同時/後のlogical timeへ置く | 前/同時はReceiptを先にRELEASED、discard ALREADY_RELEASED。後ならdiscard terminal、Receiptはlate evidence。Provider queueだけのReceiptはdrainしない |
| `MG4_CLOCK_STATUS` | cancel/resume/discard unseen pathでClock OK trusted、temporary、UNCERTAIN、permanent、zero epoch、regression | Lookup後exactly1 call。Temporary/UNCERTAINはE_CLOCK_UNCERTAIN、permanent/invalidはE_DEGRADED、error result zero/INVALID、catch-up/mutation0。Ledger replay/conflict/NOT_FOUNDはclock0 |
| `MG5_CATCHUP_FAILURE` | earlier due correctness timerのFULL commitをBUSY/IO/CORRUPT/UNKNOWN | Exact Storage mappingでmanagement success0。Bearer/TxGate/provider/entropy/callback0。Restartでtimer+management mutationの順が逆転しない |

### Deferred delivery lifetime and resource vector

Endpoint/Controller receiverはcallback前にdelivery ingressとcontext bindingを`FULL` commitします。

- 受理したapplication deliveryは`max_nonterminal_deliveries`を1件消費し、runtime ingressでは同messageの`envelope_bytes`を消費します。Durable key/valueはstorageの`16 + key + value`で別に計上します。
- Deferredを許すcallbackを呼ぶ前に`max_deferred_tokens`を1件予約できなければなりません。callback後に同期完了した場合はこの暫定予約を解放できます。
- callbackが`NINLIL_CALLBACK_DEFER`を返した場合、contextは`ninlil_delivery_complete()`成功またはtimeoutまでactiveです。payload viewはcallback returnで無効です。
- copyable `ninlil_delivery_token_t`は`context_id + generation + clock_epoch_id + expires_at_ms`を持ちます。M1aでは`context_id = delivery.transaction_id`、`generation = receiverでの同transaction callback invocation count`（checked u64、1始まり）です。TokenはRuntime内のtransaction/delivery/content digestと発行clock epochへbindingし、別Runtime/transaction/epochへ移植できません。Applicationはcallback中にvalue-copyし、pointer addressをidentity/lifetimeにしません。
- generation increment overflowではcallbackを呼ばず`NINLIL_REASON_COUNTER_EXHAUSTED`でfail closed/reconcileします。
- `NINLIL_RESOURCE_DEFERRED_TOKEN` / `max_deferred_tokens`はactive tokenだけを数えます。successful completeまたはtimeout invalidationをcommitした時点でslotを解放し、timeout時は`delivery_token_timeouts` metricを1増やします。
- tokenのportable logical sizeはABI header/paddingを除く`context_id 16 + generation 8 + clock_epoch_id 16 + expires_at_ms 8 = 48 bytes`です。Allocator実使用量とdurable token recordは、それぞれallocator limitとstorage entry formulaで別に計上します。
- `ninlil_delivery_complete()`はtoken全field、current clock epoch、trusted `now_ms <= expires_at_ms`を検査します。Runtime restartまたはclock epoch変更で旧tokenを再有効化しません。
- active token中にclock epochが変わった場合、次のrecovery/clock inputでtoken invalidation、slot解放、`RECOVERY_REQUIRED`を`FULL` commitし、old token completionを成功させません。
- invalid/expired token identityはserviceの`required_dedup_window_ms`を満たす`result_cache_retention_ms`内のbounded recordで保持します。retention中のlate/double completionは`NINLIL_E_INVALID_STATE`、retention終了後は`NINLIL_E_NOT_FOUND`です。どちらもresultを読み取らずstateを変更しません。
- timeoutでtokenをinvalidateしてもnonterminal delivery slotとdurable ingress bytesは解放しません。`on_reconcile` resultを`FULL` commitしてdeliveryがterminalになった後にだけ解放します。
- Foundation fixtureは`max_nonterminal_deliveries=32`、`max_deferred_tokens=32`、両serviceの`application_completion_timeout_ms=1,000`です。

Vector `D1_DEFER_TIMEOUT_RECONCILE`:

1. t=0にE1をControllerへdeliveryし、token context ID=`E1 transaction ID`、generation=`1`、clock epoch=`a000...0001`、`expires_at_ms=1000`をcommitしてcallbackを呼ぶ。
2. callbackは`DEFER`を返す。nonterminal/deferred countsは1/1、Receiptは0。
3. completionなしでt=1000の`DEFER_CONTEXT_TIMEOUT`を処理し、`token_valid=false + RECOVERY_REQUIRED + effect_certainty=EFFECT_POSSIBLE`をatomic commitし、deferred countを0へ戻す。nonterminal countは1のまま。
4. t=1001の旧contextへの`ninlil_delivery_complete()`は`NINLIL_E_INVALID_STATE`で、resultを読まずstateを変えない。
5. 次のruntime wakeで`on_reconcile`を1回呼ぶ。fixture application storeにevent ID recordがあるため`NINLIL_RECONCILE_KNOWN_RESULT / DURABLY_RECORDED`を返す。
6. result cacheを`FULL` commitした後だけReceiptを生成し、nonterminal count/ingress reservationを0へ戻す。invalid token recordはretentionまでboundedに保持するがdeferred countへ含めない。

t=1000に有効なdelivery-complete inputもあるvariantでは、13章priorityによりcompletionをtimeoutより先にcommitし、timeoutをinvalid-context no-opにします。同時に32 active deferred tokensがあるときの33件目はcallbackを呼ばず`NINLIL_DISPOSITION_APPLICATION_BUSY`にします。古いtokenをcomplete/timeoutした後はslotを再利用できますが、同じtoken valueを再発行してはなりません。

Vector `D2_CALLBACK_GENERATION_U64`はdurable `prior_callback_invocations = UINT32_MAX`から再deliveryします。Checked incrementは`4,294,967,296`で成功し、`delivery_count`、reconcile viewのprior count、token generationをtruncationなしのuint64値で公開/commitします。32-bit境界をlimit、wrap、negative値として扱いません。Prior count=`UINT64_MAX`ではcallback/token発行0、`RECOVERY_REQUIRED + NINLIL_REASON_COUNTER_EXHAUSTED`を`FULL` commitします。Prior=`UINT64_MAX - 1`の最後のvalid invocationはgeneration=`UINT64_MAX`を1回だけ発行でき、解決後の次incrementだけを拒否します。

### Callback registration, initialization, and borrowed lifetime

| Vector | Setup / action | Required result |
| --- | --- | --- |
| `CB1_STRUCT_COPY` | stack上callbacks structでregister成功後、structのuser/function pointerを別値へ上書き | Runtimeは登録時にcopyした元の3 pointer値だけを使用し、struct addressをdereferenceしない |
| `CB2_USER_VALUE` | user=NULL variantとnon-NULL sentinel variant | NULLもvalid。各callback第1引数はcopy済みexact値。Non-NULL pointeeはcaller-ownedでdestroy完了まで有効、Runtimeはfreeしない |
| `CB3_OUT_INIT` | callback前にout storageをpoisonする | Runtimeは毎invoke直前に全byte zero、current ABI version/`sizeof(ninlil_application_result_t)` headerを設定。Applicationがheader/reservedを変えると`CALLBACK_CONTRACT` |
| `CB4_ACTION_GATED_READ` | deliveryがDEFER/FATAL/unknown、reconcileがREDELIVER/RETRY_LATER/OUTCOME_UNKNOWN/unknownを返し、out result/evidenceへtrap pointerを置く | Runtimeはout result全体をignoreし、evidenceをdereference/copyしない。COMPLETE/KNOWN_RESULTだけ読む |
| `CB5_EVIDENCE_DEEP_COPY` | COMPLETE/KNOWN_RESULTが1〜128 byte mutable evidence bufferを返す | callback return直後、他callback/Port/public returnより先にlength検証とexact deep-copy。runtime_step return後の元buffer mutationでcache/Receipt bytes不変、元pointerをpersistしない |
| `CB6_BORROWED_VIEWS` | token、delivery/reconcile nested views、out pointerをcallback外へ保存 | Application conformance failure。DEFER時にcopy可能なのはdelivery tokenのvalueだけで、payload/nested/out pointer lifetimeはreturnで終了 |
| `CB7_RECONCILE_FIXED_BACKOFF` | local now=1,000、descriptor `retry_backoff_ms=100`でreconcileがRETRY_LATERを返し、out resultへpoison delay/trap evidenceを置く | out resultを読まず、internal retry-not-before=1,100。Application指定delay/absolute time 0。clock uncertain/epoch mismatch/checked overflowではtimer 0でfail closed |

CB1 registration failure variantはcallback/user pointerを一切保持しません。CB5でcallback stackと同時に寿命が終わるevidence objectを返すApplicationはcontract違反であり、Runtimeが非同期copyして救済したと主張しません。M1aにはservice unregisterがないため、copy済みfunction codeとnon-NULL user pointeeはRuntime destroy完了までcallable/validです。

### Callback failure, reconcile, and Disposition vectors

全vectorはcallback前`DELIVERY_STARTED`とactive tokenが`FULL` commit済みの状態から始めます。

| Vector | Application behavior | Required durable result |
| --- | --- | --- |
| `F1_CALLBACK_FATAL` | `NINLIL_CALLBACK_FATAL`を返す | token invalidation、active slot release、`RECOVERY_REQUIRED`、`NINLIL_EFFECT_CERTAINTY_POSSIBLE`、reason=`NINLIL_REASON_APPLICATION_FAILED`を1つの`FULL` commit。health=`NINLIL_HEALTH_DEGRADED`、positive Receipt 0 |
| `F2_CALLBACK_UNKNOWN` | callback action=`0xffffffff` | F1と同じだがreason=`NINLIL_REASON_CALLBACK_CONTRACT`。unknown値をCOMPLETE/DEFERへfallbackしない |
| `F3_COMPLETE_INVALID` | `NINLIL_CALLBACK_COMPLETE`だがapplication resultの1 fieldがinvalid | F2と同じ。invalid resultを送信せず、同じRuntime instanceで同Deliveryを再callbackしない |
| `F4_RECONCILE_UNKNOWN` | `RECOVERY_REQUIRED`でreconcile action=`0xffffffff` | stateを保持、health=`DEGRADED`、reason=`CALLBACK_CONTRACT`、Receipt/Disposition/result commit 0、同じrecovery passで再callback 0 |
| `F5_RECONCILE_OUTCOME_UNKNOWN` | `NINLIL_RECONCILE_OUTCOME_UNKNOWN` | effect possibleとexact OUTCOME_UNKNOWN Dispositionを`FULL` commit、positive Receipt 0 |

F1〜F3のrecovery commitがdefinite failure/unknownならpositive Receiptを出さずdeliveryをfenceし、RuntimeをDEGRADEDに保ちます。Reopen後にactive tokenを復元せず、durable recordを再読して`on_reconcile`またはsafe idempotent recoveryへ進めます。F4/F5をcallback returnそのものだけで成功evidenceとして扱いません。

F1〜F3はE1 Controller receiverで`controller.before_callback_recovery_commit` / `after`、C1 Endpoint receiverで`endpoint.before_callback_recovery_commit` / `after`をそれぞれ実行します。Before-hook crashではafter 0、commit unknown/definite failureでもafter 0/Receipt 0です。Recoveryが同じ未commit transitionを再実行する場合もgeneric recovery hookへaliasせず同じrole-specific pairを通ります。F4/F5のreconcile result commitは`*_before_reconcile_commit` / `after`でありcallback-recovery pairを使いません。

Disposition conformanceは12章のexact matrixを全row実行します。`retry_delay_ms=max`は`NINLIL_M1A_MAX_RETRY_DELAY_MS`です。

| Vector | Disposition | Effect certainty | Retry guidance | Reason | Delay domain |
| --- | --- | --- | --- | --- | --- |
| `DV1` | `NINLIL_DISPOSITION_RETRY_LATER` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_SAME_AFTER` | `NINLIL_REASON_RECONCILE_RETRY_LATER` | 0〜max |
| `DV2` | `NINLIL_DISPOSITION_INVALID_PAYLOAD` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_MODIFIED` | `NINLIL_REASON_APPLICATION_FAILED` | 0 only |
| `DV3` | `NINLIL_DISPOSITION_UNSUPPORTED_SCHEMA` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_MODIFIED` | `NINLIL_REASON_APPLICATION_FAILED` | 0 only |
| `DV4` | `NINLIL_DISPOSITION_UNAUTHORIZED_SERVICE` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_MODIFIED` | `NINLIL_REASON_TARGET_UNAUTHORIZED` | 0 only |
| `DV5` | `NINLIL_DISPOSITION_STALE_NOT_APPLIED` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_NEVER` | `NINLIL_REASON_APPLICATION_FAILED` | 0 only |
| `DV6` | `NINLIL_DISPOSITION_APPLICATION_BUSY` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_SAME_AFTER` | `NINLIL_REASON_RECEIVER_UNAVAILABLE` | 0〜max |
| `DV7` | `NINLIL_DISPOSITION_APPLY_FAILED` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_SAME_AFTER` | `NINLIL_REASON_APPLICATION_FAILED` | 0〜max |
| `DV8` | `NINLIL_DISPOSITION_APPLY_FAILED` | `NINLIL_EFFECT_CERTAINTY_POSSIBLE` | `NINLIL_RETRY_OPERATOR_ACTION` | `NINLIL_REASON_APPLICATION_FAILED` | 0 only |
| `DV9` | `NINLIL_DISPOSITION_VERIFY_FAILED` | `NINLIL_EFFECT_CERTAINTY_POSSIBLE` | `NINLIL_RETRY_OPERATOR_ACTION` | `NINLIL_REASON_APPLICATION_FAILED` | 0 only |
| `DV10` | `NINLIL_DISPOSITION_CAPACITY_EXHAUSTED` | `NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN` | `NINLIL_RETRY_SAME_AFTER` | `NINLIL_REASON_CAPACITY_EXHAUSTED` | 0〜max |
| `DV11` | `NINLIL_DISPOSITION_OUTCOME_UNKNOWN` | `NINLIL_EFFECT_CERTAINTY_POSSIBLE` | `NINLIL_RETRY_OPERATOR_ACTION` | `NINLIL_REASON_OUTCOME_UNKNOWN` | 0 only |

各valid rowは`NINLIL_APP_RESULT_DISPOSITION`、evidence stage NONE、empty evidenceとしてcallback complete、deferred complete、reconcile KNOWN_RESULTのうち適用可能なpathで最低1回受理し、result cache/token invalidationをcommit後にだけ同じDisposition/certainty/guidance/delayのBearer DISPOSITIONを生成します。Bearer messageにreason fieldはなく、sender reducerがこの表からstable reasonへexact写像します。Positive evidence vectorはsupported non-zero stage、disposition NONE、reason NONE、effect certainty NONE、retry guidance NEVER、delay 0だけを受理します。

Negative matrixは各valid rowからeffect certainty、retry guidance、reason、delay、evidence stage、evidence lengthを1 fieldずつ変えます。Delay=max+1、0-only rowのdelay=1、`EFFECT_POSSIBLE + RETRY_SAME_AFTER`、`NO_EFFECT_PROVEN + RETRY_OPERATOR_ACTION`を必ず含めます。すべて`CALLBACK_CONTRACT`へfail closedし、positive Receipt、Bearer send、result cache successは0です。Bearer ingressの同じmutationもinvalid messageとしてstateを変えません。

### Attempt timeout and retry vectors

Foundation fixtureの両serviceは`attempt_receipt_timeout_ms=1,000`、`retry_backoff_ms=100`です。Public Disposition/resultの`retry_delay_ms`は受信側local clockで測るrelative durationで、0は「相手から追加delay指定なし」、最大は`NINLIL_M1A_MAX_RETRY_DELAY_MS=600,000`です。上限超過はinvalid result/decisionです。

Attempt ID candidateはRuntimeのactive/retained attempt ID index全体へuniqueなnon-zero 16 bytesでなければなりません。Coreは1 ID生成につき`entropy.fill(16)`を最大4回だけ呼び、Port failure、partial fill、all-zero、collisionもそれぞれ1 drawとして数えます。Attempt index追加はATTEMPT_PREPARE recordと同じ`FULL` transactionです。

Vector `ID1_FOURTH_CANDIDATE_VALID`はscripted entropy test doubleから次を順に返します。

1. `00000000000000000000000000000000`
2. retained attempt ID `11111111111111111111111111111111`
3. restart前からretainedする別attempt ID `22222222222222222222222222222222`
4. unique ID `33333333333333333333333333333333`

4件目をvalidとして停止し、attempt ID=`3333...3333`のATTEMPT_PREPARE/indexを1回だけcommitします。Attempt budget消費=1、permit acquire=1、Bearer sendは最大1です。先の3 candidateにattempt/index/timer/reservationを作りません。Collision lookupはrestartを跨ぐため、3件目を「memoryにない」として受理してはなりません。

Vector `ID2_FOUR_INVALID`は`zero / retained-1 / retained-2 / zero`の4件を返します。結果は`NINLIL_E_ENTROPY`、Runtime health=`NINLIL_HEALTH_DEGRADED`で、ATTEMPT_PREPARE record、attempt-index追加、attempt budget消費、TxPermit acquire、Bearer send、timeout timerはすべて0です。5回目をdrawせず、PRNG/clock/device ID/counter fallbackを使いません。Existing transaction、payload、retry cycleは失いません。

Vector `ID3_PORT_FAILURE_COUNTS`は1回目をtemporary Port failure、2〜4回目をinvalid candidateにします。Coreのcandidate budgetは4で尽きますが、14章provider ruleによりfailed call自体はdeterministic entropy stream counterを進めません。Core call countとprovider block counterを混同しません。Collision lookup storage failureは`NINLIL_E_ENTROPY`へ変換せず、対応するstorage statusでfail closed/send 0です。

```text
effective_retry_delay_ms = max(retry_backoff_ms, disposition.retry_delay_ms)
internal_retry_not_before_ms = checked_add(now_ms, effective_retry_delay_ms)
```

- accepted/custody/LOST_UNKNOWNまたはCORRUPT/invalid possible-delivery sendごとにattempt IDへbindingした`ATTEMPT_RECEIPT_TIMEOUT`をsend observation時刻+1,000へscheduleします。Definitive no-sendではtimer 0です。
- required Receiptがtimeoutと同時刻なら13章priorityでReceiptを先にcommitし、timeoutはstale no-opです。
- `R1C_COMMAND_ACCEPTED_TIMEOUT`: t=0のC1 sendがACCEPTED、required Receiptなし。t=1000のcurrent-attempt timeoutは`controller.before_command_attempt_timeout_commit` / `after`を通り、`AWAITING_EVIDENCE + NINLIL_EFFECT_CERTAINTY_POSSIBLE`を`FULL` commitします。NO_EFFECTやRETRY_SAME_AFTERへ変換せず、timeoutだけでRETRY_WAIT/new attemptへ進みません。
- R1Cのsafe retry variantはC1のIDEMPOTENT guard、dispatch fenceなし、required evidence未達、attempt budget残、trusted deadline epoch、`checked(1000 + 100) < 5000`が全部成立するため、t=1100以後のRETRY_DUEでだけnew attemptを準備できます。APPLICATION_DEDUPなら同じtransaction/target/generation/content digestとrequired durable dedup windowを維持する場合だけ同様です。1 guardでも不成立ならsend 0でevidence closeまで待ちます。
- `R1E_EVENT_ACCEPTED_TIMEOUT`: t=0のE1 send accepted、t=1000 timeoutは`endpoint.before_event_attempt_timeout_commit` / `after`を通ります。Event ID dedup/custody/payloadを保持し、fixed backoff後に同じcycleの次attemptへ進み、8 attempts後だけPARKED_RETRYです。Command timeout hookを使いません。
- `R1S_STALE_TIMEOUT`: old attempt timeout、または同時刻に先にdurable ingressしたvalid Receipt/Dispositionへ負けたtimeoutはstate/budget/timer不変で、command/event timeout hookも発生しません。Old attempt bindingのlate Receiptは新attempt後も検証・保持し、required stageならcurrent transactionへ収束できます。
- `R1N_DEFINITE_NO_ACCEPT`: Bearer未受理statusを分割します。WOULD_BLOCK/UNAVAILABLEはNO_EFFECT_PROVENでReceipt timeout 0、Commandはfixed-backoff retry、EventはBEARER_UNAVAILABLE early parkです。DENIEDはNO_EFFECT_PROVENでもautomatic retry 0、Command FAILED_DEFINITIVE、Event APPLICATION_REMEDIATION parkです。ACCEPTED/DURABLE_CUSTODY/LOST_UNKNOWN/CORRUPT-invalidと混同しません。
- `R2_REMOTE_LATER`: t=200、exact matrixのNO_EFFECT_PROVEN Disposition `retry_delay_ms=550`は`200 + max(100, 550)=750`です。
- `R3_LOCAL_BACKOFF`: t=200、`retry_delay_ms=50`または0は`200 + 100=300`です。送信側absolute clockを比較しません。
- `R4_COMMAND_EVIDENCE_CLOSE`: R1C後もrequired evidence未達でC1 evidence close=6000へ達すると、`controller.before_evidence_close_commit` / `after`を通り`NINLIL_OUTCOME_UNKNOWN + NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING`を`FULL` commitします。EventFactにはこのtimer/hookを生成しません。
- checked addition overflowまたはclock epoch/trust喪失時はretry timerを生成せず、13章のclock-uncertain recoveryへ進みます。
- DesiredStateCommandはsafe apply guardを満たし、計算結果がeffect deadline未満の場合だけ再dispatchします。
- EventFactは1 cycle最大8 attemptsです。8件枯渇後は`PARKED_RETRY`でpayloadを保持し、fresh Bearer availability epoch + `available=1`または一意resume以外でbudgetを補充しません。

### Canonical harness trace

Replay artifactは最低限、fixture revision、fault-script digest、seed、port versions、event records、final public snapshots、invariant resultを含めます。

Harness event traceのcross-implementation digestは次のbinary `trace-v1`へSHA-256を適用します。

```text
magic                 4 bytes  ASCII "NTR1"
record_count          u64 big-endian
per record:
  sequence            u64 big-endian
  due_time_ms          u64 big-endian
  insertion_ordinal    u64 big-endian
  event_kind           u16 big-endian
  runtime_name_length  u16 big-endian
  runtime_name         exact ASCII bytes; 0 length when absent
  script_index         u32 big-endian, 0xffffffff when absent
  subject_id_present   u8
  subject_id           16 bytes when present
  attempt_id_present   u8
  attempt_id           16 bytes when present
  status_domain        u8: NONE=0, API=1, STORAGE=2, BEARER=3,
                          PORT=4, TX_GATE=5, ORIGIN_AUTH=6
  status               u32 big-endian, exact value in status_domain
```

Event kind codeは`1=SCRIPT_ACTION`、`2=RUNTIME_WAKE`、`3=BEARER_DELIVERY`、`4=RUNTIME_RESTART`、`5=TIMER`、`6=CANCELED_NOOP`です。可変diagnostic text、pointer、host timestampをdigestへ含めません。Runtime内部の正しさは13章のstate/reducer vectorとfinal public snapshotで別に比較します。

`sequence`はtraceへ実際にappendしたrecordの1始まりchecked uint64 indexです。First record=1で、event kind 6のCANCELED_NOOPも1件を消費します。Queueへ入れただけ、manifest validationで拒否、実行前crashでappendされなかったeventは消費しません。Appendとsequence assignmentは不可分でgap/reuseを作らず、`UINT64_MAX` recordをappendした後の次recordはscenario failureとして停止し、wrap/digest成功を生成しません。`insertion_ordinal`はevent queueへenqueueした順の別の**0始まり**checked counterで、first enqueue=0、cancel後も元値を保持します。したがって両fieldを相互代用しません。

`runtime_name`はmanifestで1〜63 byteのprintable ASCII `[A-Za-z0-9._-]`、scenario内uniqueです。Runtime非所属recordだけlength 0です。これ以外のname、u16で表現不能な可変field、duplicate runtime nameはtrace生成前のmanifest errorです。Scenario name自体はtrace-v1 recordへencodeしません。

### Same-time durable-ingress boundary

13章のsame-time reducer priorityは、Coreがすでにdurable canonical inputへ変換したものだけに適用します。Bearer provider queueにcopyが到着しただけでは`VALID_RECEIPT`ではありません。`ninlil_event_resume()`、`ninlil_event_discard()`等のpublic management APIが暗黙に`receive_next`/drain/stepを行うことは禁止です。

Collision vector `S1_RECEIPT_BEFORE_MANAGEMENT`はt=2,000に次のordinal順を明示します。

1. `BEARER_DELIVERY`: required Receipt copyをController provider queueへdueにし、current-time Runtime wakeをenqueueする。
2. `RUNTIME_WAKE`: 1回目の`ninlil_runtime_step()`がcopyをreceive/validateし、existing Event ownerへdurable ingress sequence付きinputを`FULL` copyする。Stage-4 candidate cut後のcopyなのでこのstepではreduceせずcurrent-time wakeを残す。
3. `RUNTIME_WAKE`: 2回目のstepがowner ringで`VALID_RECEIPT`をreduce/`FULL` commitする。
4. `SCRIPT_ACTION`: `controller.after_receipt_commit` hookから同じt=2,000へmanagement callをenqueueし、Event discardまたはresumeを呼ぶ。

すべて同じ`due_time_ms`ですが、生成順のinsertion ordinalにより0→1→2→3です。Reducerはdurable Receiptをpriority 1、discardを3、resumeを8として適用します。Required ReceiptならEventはSATISFIED + RELEASEDとなり、後続discard/resumeは`ALREADY_RELEASED`です。

`S2_PROVIDER_ONLY_IS_LATE`ではmanagement SCRIPT_ACTIONを先にcommitし、その後同時刻numberのBearer copyがprovider queueへ到着します。Management APIはhidden drainしません。後でRuntime stepがdurable ingressしたReceiptは、先にcommit済みdiscard等へ遡ってpriority適用せずlate evidenceとして扱います。Harnessはprovider arrival timestampやReceipt issuer `evidence_time`でdurable ingress sequenceを並べ替えません。

Plain time-trigger management actionをscenario初期化時に先にenqueueしておき、後から同じdue timeへ到着したBearer eventを13章priorityだけで追い越させてはなりません。Priority衝突testはS1のafter-ingress hook topology、または同等に「Bearer delivery→current-time step commit→management enqueue」のordinalをfixture manifestで固定します。

### Transaction sequence and query/list vectors

このsuiteは12章`ninlil_transaction_list()`のstable transaction enumerationを検査します。mutation log、change feed、offset paginationとして実装してはなりません。HarnessはC1/E1 entropy goldenとは別scenario resetでscripted entropy/timeとpublic admission/reducer inputを使い、実装固有storage keyを直接書かずに次のdurable observable stateを確立します。`QT1`〜`QT3`はtest alias、transaction ID bytesは表の値です。Service identityの全fieldは後述C1/E1 presetと同値です。

| Alias | Transaction ID | Service preset | Family/state/outcome/reason | Admission epoch/time | Sequence | Revision |
| --- | --- | --- | --- | --- | ---: | ---: |
| `QT1` | `b0000000000000000000000000000001` | C1 `absolute-state` | `DESIRED_STATE / READY / NONE / NONE` | `a000...0001 / 100` | 1 | 3 |
| `QT2` | `b0000000000000000000000000000002` | E1 `durable-event` | `EVENT_FACT / TERMINAL / SATISFIED / REQUIRED_EVIDENCE_MET` | `a000...0001 / 200` | 2 | 5 |
| `QT3` | `b0000000000000000000000000000003` | C1 `absolute-state` | `DESIRED_STATE / READY / NONE / NONE` | `a000...0002 / 250` | 3 | 1 |

Fixtureのnext transaction sequence counterは3です。`transaction_sequence`とcounterは同じstorage namespaceのdurable state、各summaryのinline text IDはcaller-owned outputです。各call前にpageと全item slotのABI headerを初期化し、capacity 0ならitemsはNULL、capacity > 0ならnon-NULLにします。

| Vector | Query and page capacity | Required result |
| --- | --- | --- |
| `QRY1_FIRST_PAGE` | after=0、time filter disabledかつepoch/time zero、family mask=0、terminal=1、nonterminal=1、capacity=2 | `NINLIL_OK`; item=`QT1, QT2`の順、count=2、next=2、has_more=1 |
| `QRY2_SECOND_PAGE` | after=2、他はQRY1、capacity=2 | `NINLIL_OK`; item=`QT3`、count=1、next=3、has_more=0 |
| `QRY3_EMPTY_PAGE` | after=3、他はQRY1、capacity=2 | `NINLIL_OK`; count=0、nextはinputと同じ3、has_more=0、item slotsは変更しない |
| `QRY4_TERMINAL_EVENT` | after=0、time filter disabled、family mask=`NINLIL_FAMILY_MASK_EVENT_FACT`、terminal=1、nonterminal=0、capacity=2 | `QT2`だけ、next=2、has_more=0 |
| `QRY5_NONTERMINAL_COMMAND` | after=0、time filter disabled、family mask=`NINLIL_FAMILY_MASK_DESIRED_STATE`、terminal=0、nonterminal=1、capacity=2 | `QT1, QT3`、next=3、has_more=0 |
| `QRY6_EPOCH_BOUND_TIME` | after=0、filter enabled、epoch=`a000...0001`、admitted-at-or-after=150、family mask=0、terminal=1、nonterminal=1、capacity=2 | `QT2`だけ。数値250の`QT3`は異なるepochなので含めない |
| `QRY7_ENDPOINT_INBOUND_COMMAND` | Endpoint Command receiverがinbound C1 Delivery/result-cacheを保持中にそのtransaction IDをqueryし、listも実行 | query=`NINLIL_E_NOT_FOUND`/snapshot zero、listに列挙0、namespace sequence counter不変。Callback中も同じ |
| `QRY8_CONTROLLER_INBOUND_EVENT` | Controller Event receiverがinbound E1 Delivery/result-cacheを保持中にそのtransaction IDをqueryし、listも実行 | QRY7と同じ。Inbound recordへsequence/assuranceを合成しない |

`has_more`は各callのstorage read snapshot内で、全filter適用後に`next_after_transaction_sequence`より大きいmatching recordがある場合だけ1です。別page callは新しいsnapshotを使用できます。

Pagination mutation vectorでは、`QRY1_FIRST_PAGE`の後に`QT1`をdurable `ATTEMPT_PREPARED`（public `TXN_DISPATCHING`）へ変える1回の`FULL` commitを行います。`QT1.record_revision`は3から4、sequenceは1のままです。その後Runtimeをcrash/restartして`QRY2_SECOND_PAGE`を実行しても、`QT1`を再列挙せず`QT3`だけを返します。after=0で改めてlistすれば`QT1`はrevision=4で一度だけ現れます。これはrevisionがchange cursorではないことの必須negative testです。

Revision saturation vectorはrevision=`UINT64_MAX - 1`のnonterminal recordへ2回のvalid state mutationをそれぞれ`FULL` commitします。1回目で`UINT64_MAX`、2回目も`UINT64_MAX`です。2回目のstate mutation自体は成功し、sequenceは不変です。Definite commit failureではstate/revisionをどちらも進めず、commit unknownではreopen/reconcile後に「両方進んだ」か「両方進んでいない」のどちらかだけを観測します。

Sequence restart vectorでは、counter=3のfixtureをrestartした後、C1からidempotency keyをASCII `query-seq-4`、generationを2へ変えたwell-formed submissionをtrusted time 300でadmitします。返されたtransaction IDをalias `QT4`として捕捉し、そのsnapshotがsequence=4、revision=1、admission epoch/time=`a000...0001 / 300`であることを検査します。さらにrestart後、after=3のlistは`QT4`を一度だけ返してnext=4とします。Transaction IDの生成方式は本vectorの比較対象ではありませんが、捕捉したIDはsubmit result、query、list、restart後でbyte一致しなければなりません。

Sequence allocationの`FULL` commitがunknownになったvariantは最初のsubmitを`NINLIL_E_STORAGE_COMMIT_UNKNOWN`にします。Ground truthがcommittedならcounter=4と`QT4` transaction/mapping/reservationがすべて存在し、not-committedならすべて存在しません。同じsubmissionをrestart後にretryしてreconcileした最終状態は、どちらもsequence=4のtransactionがexactly 1件で、counter skip、duplicate mapping、reservation leakを0件とします。

Counter exhaustion vectorはdurable next sequence counter=`UINT64_MAX`からwell-formed unique C1 submissionを行います。API resultは`NINLIL_OK + NINLIL_SUBMISSION_REJECTED + NINLIL_REASON_COUNTER_EXHAUSTED`で、新transaction、mapping、reservation、counter mutationは0件、既存transactionは不変です。

Invalid queryはsemantic reducer/storage readより前に拒否します。

| Invalid input | Required result |
| --- | --- |
| terminal=0かつnonterminal=0、またはboolean fieldが0/1以外 | `NINLIL_E_INVALID_ARGUMENT` |
| time filter disabledなのにepochまたはtimeがnon-zero | `NINLIL_E_INVALID_ARGUMENT` |
| time filter enabledなのにepochがall-zero | `NINLIL_E_INVALID_ARGUMENT` |
| family maskに2つのdefined bit以外がある | `NINLIL_E_INVALID_ARGUMENT` |
| query/pageのreserved fieldがnon-zero | `NINLIL_E_INVALID_ARGUMENT` |
| capacity=0でitems non-NULL、またはcapacity > 0でitems NULL | `NINLIL_E_INVALID_ARGUMENT` |

Invalid callではitem bytes、page cursor、durable stateを変更しません。`record_revision`はCAS、pagination guard、sorting keyに使用せず、1 transactionをstate mutationごとに別itemとして返しません。

Transaction snapshot projection vectorsはouter、target slot、nested assuranceをnon-zero poisonで初期化し、全fieldを比較します。

| Vector | State sequence | Required projection |
| --- | --- | --- |
| `QPX1_COMMAND_ALL_STATES` | C1 READY→ATTEMPT_PREPARED→accepted AWAITING→transport RETRY_WAIT→cancel pending/too-late→SATISFIED、別variantでEXPIRED/CANCELLED/FAILED/UNKNOWN | 12章internal→public state、active/terminal outcome/reason/deadline verdictを各commit直後にexact比較。Top/target state/outcome/reason/latestは常に一致 |
| `QPX2_EVENT_ALL_STATES` | E1 HELD_READY→ATTEMPT_PREPARED→AWAITING→RETRY_WAIT→5 park cause各1→resume→SATISFIED、別variantでaudited discard | Event ID/generation/deadline/park/retry cycle/attempt/cumulative/spool revision/late/discard fieldを各stateでexact比較 |
| `QPX3_FAMILY_UNUSED_ZERO` | Command/Event snapshotをpoisonしquery | Command event/cycle/spool/discard fields、Event generation/deadline fields、non-PARKED causeを12章zero/constantへ上書き。Pointer/header/capacity rule以外のpoison残存0 |
| `QPX4_REVISION_AND_LATE_EVIDENCE` | terminal後にnew late material、duplicate、raw-full summary update。Event revision MAX-1→required Receipt/discard terminal MAX後にもunique/duplicate late material | Outcome/terminal reason/deadline verdict不変、latest/late flagとrecord revisionだけ規則どおり進む。Event spool revisionは全late caseでMAX維持、restart不変。Top/target一致、duplicate no material/spool-revision mutation |

## Foundation fixture identity and policy

### Stable identity set

次の16-byte IDはhex表示どおりのnetwork byte orderです。文字列runtime IDはharness内だけで、Ninlil identityとして送信しません。

| Meaning | Value |
| --- | --- |
| site domain | `10000000000000000000000000000001` |
| controller device | `20000000000000000000000000000001` |
| controller Runtime | `21000000000000000000000000000001` |
| controller application instance | `30000000000000000000000000000001` |
| endpoint device | `40000000000000000000000000000001` |
| endpoint Runtime | `41000000000000000000000000000001` |
| endpoint installation | `50000000000000000000000000000001` |
| controller sink installation | `50000000000000000000000000000002` |
| endpoint application instance | `60000000000000000000000000000001` |
| synthetic origin grant | `70000000000000000000000000000001` |
| virtual permit issuer | `80000000000000000000000000000001` |
| C1 / E1 virtual permit | `a82ca19b607f15a81ab5984de23aec7a` / `8cae0f2e73895edf41b8bba899852078` |
| EventFact event ID | `90000000000000000000000000000001` |
| virtual clock epoch | `a0000000000000000000000000000001` |
| C1 controller metrics epoch | `968198a87ecbad2092b55f929da076a3` |
| C1 transaction / attempt 1 / cancel attempt | `0d5382f07b9c59639f7c1957ae22fea7` / `5dd9578bd99d35ff819efba06edcb33e` / `836926954fc0c8111965b6c4ff3f369e` |
| E1 endpoint metrics epoch | `4faf7975a1ca8185196dcb80ccd0bfa1` |
| E1 transaction / attempt 1 | `a0726cd8b13d4cab041a06a5fce92ca4` / `a8c780783f852e11cb4fdd5188d44ffc` |
| query alternate admission epoch | `a0000000000000000000000000000002` |
| query transaction QT1 | `b0000000000000000000000000000001` |
| query transaction QT2 | `b0000000000000000000000000000002` |
| query transaction QT3 | `b0000000000000000000000000000003` |
| A1 discard operation | `c0000000000000000000000000000001` |
| A1 discard actor | `d0000000000000000000000000000001` |

共通値はsite membership epoch=`1`、installation binding epoch=`1`、descriptor revision=`1`です。runtime manifestは次を固定します。

- harness name=`controller-1`、Runtime ID=`2100...0001`、role=`CONTROLLER`、environment=`TEST`、entropy stream=`1`、storage namespace length=19/hex=`4e494e4c494c2d464f554e444154494f4e0001`、local identity=`device 2000...0001 / installation 5000...0002 / site 1000...0001 / flags 7 / epochs 1,1`
- harness name=`endpoint-1`、Runtime ID=`4100...0001`、role=`ENDPOINT`、environment=`TEST`、entropy stream=`2`、storage namespace length=19/hex=`4e494e4c494c2d464f554e444154494f4e0002`、local identity=`device 4000...0001 / installation 5000...0001 / site 1000...0001 / flags 7 / epochs 1,1`

両Runtimeは`terminal_retention_ms=86,400,000`、`result_cache_retention_ms=86,400,000`、`observation_retention_ms=3,600,000`です。Resource profileは12章`NINLIL-FOUNDATION-SMALL-1`を全field明示し、`max_cancel_attempts_per_transaction=1`です。Command admissionはremote cancel attempt/record/outbox metadata 1件をlocal reservationへ含めます。

両Runtimeのmetrics `started_clock_epoch_id`は`a000...0001`、started timeは0です。C1/E1 transaction snapshotの`admission_clock_epoch_id`も同epochです。C1の`deadline_clock_epoch_id`は同epoch、E1のdeadline epochだけはall-zeroです。

### Fixture capability

12章`ninlil_service_descriptor_t`の全fieldを次で固定します。未記載default、0のdefault解釈、実装別補完は禁止です。

| Descriptor field | C1 Reliable Command | E1 Durable Event |
| --- | --- | --- |
| namespace ID | `org.ninlil.examples` | `org.ninlil.examples` |
| service ID | `absolute-state` | `durable-event` |
| schema ID | `absolute-state` | `durable-event` |
| descriptor revision | `1` | `1` |
| descriptor digest | `SHA-256(1):4a36772bfa7a683c4b203da25f990bd8903f053515bfe144077283a26c8e0abd` | `SHA-256(1):f64b7c4abf5b9db38b1c9fef0f0e8c341b56caddadb291ebc5456ccbd2aa321b` |
| local application instance | Controller registration=`3000...0001`; Endpoint registration=`6000...0001` | Endpoint registration=`6000...0001`; Controller registration=`3000...0001` |
| schema major/minor min/max | `1 / 0 / 0` | `1 / 0 / 0` |
| family | `NINLIL_FAMILY_DESIRED_STATE` | `NINLIL_FAMILY_EVENT_FACT` |
| direction | `NINLIL_DIRECTION_DOWNLINK` | `NINLIL_DIRECTION_UPLINK` |
| admission authority | `NINLIL_AUTHORITY_CONTROLLER_ONLY` | `NINLIL_AUTHORITY_ORIGIN_WITH_GRANT` |
| apply contract | `NINLIL_APPLY_IDEMPOTENT` | `NINLIL_APPLY_APPLICATION_DEDUP` |
| custody policy | `NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE` | `NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE` |
| supported evidence mask | RECEIVED + DURABLY_RECORDED + APPLIED = `14` | RECEIVED + DURABLY_RECORDED = `6` |
| logical payload limit | `1,024` | `1,024` |
| target limit | `1` | `1` |
| inflight limit | `32` | `32` |
| max attempts/target/cycle | `8` | `8` |
| admission window ms | `10,000` | `10,000` |
| max admissions/window | `20` | `8` |
| max payload bytes/window | `20,480` | `8,192` |
| minimum deadline ms | `5,000` | `NINLIL_NO_DEADLINE` |
| maximum deadline ms | `5,000` | `NINLIL_NO_DEADLINE` |
| maximum evidence grace ms | `1,000` | `0` |
| attempt Receipt timeout ms | `1,000` | `1,000` |
| retry backoff ms | `100` | `100` |
| application completion timeout ms | `1,000` | `1,000` |
| required dedup window ms | `86,400,000` | `86,400,000` |

全ABI headerはcurrent version/size、`reserved_zero_u16`と`reserved_zero_u32`は0です。C1 fixture payloadはexactly 9 bytes、E1はexactly 10 bytesですが、descriptor hard limitは表の1,024です。C1 sender Controllerはcallbackなし、receiver Endpointは`on_delivery`。E1 sender Endpointはcallbackなし、receiver Controllerは`on_delivery + on_reconcile`を登録します。

Capability mismatch、old membership/binding epoch、unsupported evidenceはadmissionまたはdeliveryで明示拒否し、fixtureだから省略してはなりません。

### Admission quota vectors

Quota suiteは12章のexact keyを使い、receiver ingressをcounterへ混ぜません。

| Vector | Setup / operation | Required result |
| --- | --- | --- |
| `AQ1_SCOPE_ATOMIC` | 同じapplication/service/revision/digest keyで新規admission | transaction/mapping/inflight/window count/payload bytesを1 FULL commitで増加。Runtime recreate/local identity rotationでreset 0。別descriptor revision/digestは別quota key |
| `AQ2_INFLIGHT_RELEASE` | inflight=limitからnew submit、次に既存1件をterminal commitして再submit | 最初はREJECTED/CAPACITY_EXHAUSTED/SAME_AFTER/delay0。Terminal commit OKとatomic -1後だけ次をadmit。Retained terminalはcount 0 |
| `AQ3_COUNT_BOUNDARY` | same epoch/windowでcount=max-1、timeをwindow end-1/endへ進める | max exactはadmit、同window次はRATE_EXHAUSTED、delay=1。Boundary exactでnew key/count0からadmit |
| `AQ4_BYTE_BOUNDARY` | prospective logical payload bytes=max exactとmax+1 | Exactはadmit、+1はRATE_EXHAUSTED/window remaining。Event 2,560-byte reservation/envelope/storage overheadをcounterへ加えない |
| `AQ5_NO_DOUBLE_CHARGE` | ALREADY、conflict、rejected、provider/API errorを各実行 | quota/transaction sequence/provider-call規則どおり変化0。Event ALREADY/conflictはprovider 0 |
| `AQ6_ORIGIN_REQUEST` | Event new candidateでprovider DENY、ALLOW後Core quota/grant超過 | Requestはcandidate前count、namespace-global active spool count/bytes、exact epoch/window startを渡す。DENYはprovider tuple、ALLOW後Core recheckは12章exact reason/delay |
| `AQ7_COMMIT_UNKNOWN` | admissionとterminal quota commitをhidden committed/not-committedで各実行しrestart | transaction/mapping/quota all-or-none、二重加算0。Terminalはauthoritative resolution前にinflight解放済みと推測しない |
| `AQ8_SINGLE_PRECEDENCE` | counter headroom、provider DENY、service inflight/count/bytes、grant payload/active count/active bytes/rate、Runtime capacityを同時に複数超過させ、1つずつ解除 | Syntax/idempotency→clock→transaction counter→owner counter→provider→Core tableの最初の1 reason/delayだけ。Rejected mutation/entropy 0 |
| `AQ9_BOUNDED_BUCKET` | 100,000 windowsとclock epoch changeを跨ぎ、各windowで0/1 admission、commit unknown両truthを混在 | quota keyごとcurrent bucket exactly 1、old history 0。New key/count/bytes atomic overwrite、restart後同値、skip windowでrecord増加0 |
| `AQ10_OWNER_COUNTER_ATOMIC` | transaction/owner counter headroom、provider status、quota、entropy、admission commit unknownをcross-product | ALREADY/conflictはclock/counter/provider0。Counter exhaustionはprovider/entropy/reservation0。Successは両counter+owner+transaction/mapping/quota all in 1 FULL、unknown all-or-none、orphan owner0 |

上記descriptor digestはfixture manifestの固定入力です。Canonical Submission encoderはdescriptorを再hashせず、登録済みsnapshotのalgorithmと32 bytesを取り込みます。Namespace、service、schema、direction、authority、family、apply/custody contract、limitのいずれかを変えるdescriptorは同じdigestを再利用してはなりません。

### Role × family and callback-shape vectors

M1a registration/submit matrixは次の4行だけです。Local sender/receiverはrole、family、required directionからCoreが導出し、caller指定fieldを追加しません。

| Runtime | Family / descriptor | Local side | Required callbacks | Submit |
| --- | --- | --- | --- | --- |
| Controller | DesiredState / DOWNLINK + CONTROLLER_ONLY | Command sender | delivery NULL / reconcile NULL | allowed |
| Endpoint | DesiredState / DOWNLINK + CONTROLLER_ONLY | Command receiver | delivery required。APPLICATION_DEDUPはreconcile required、IDEMPOTENTはNULL可 | direction rejection |
| Endpoint | EventFact / UPLINK + ORIGIN_WITH_GRANT | Event sender | delivery NULL / reconcile NULL | allowed |
| Controller | EventFact / UPLINK + ORIGIN_WITH_GRANT | Event receiver | delivery required / reconcile required | direction rejection |

| Vector | Mutation / call | Required result |
| --- | --- | --- |
| `RF1_FOUR_VALID` | 上表4行をexact登録 | 4 service handles。C1/E1 sender/receiver fixture callback形状と一致 |
| `RF2_DESCRIPTOR_CONTRACT_FIRST` | family固有direction、authority、apply contractのいずれかを変更 | callback shape評価前に`NINLIL_E_UNSUPPORTED`、service NULL、partial registration 0 |
| `RF3_CALLBACK_SHAPE` | 各行でdelivery/reconcileを1 pointerだけ逆にする、またはcallbacks struct NULL | `NINLIL_E_INVALID_ARGUMENT`、service NULL、callback/user保持0 |
| `RF4_RECEIVER_SUBMIT` | Endpoint Command receiverまたはController Event receiver handleへwell-formed submit | `NINLIL_OK + NINLIL_SUBMISSION_REJECTED + NINLIL_REASON_UNSUPPORTED_DIRECTION + NINLIL_RETRY_MODIFIED + delay 0`。transaction/digest/assurance zero、entropy/auth/reservation/storage 0 |
| `RF5_WRONG_DIRECTION_INGRESS` | sender handleへforward APPLICATION、receiver handleへreverse family message | callback/reducer 0、invalid-ingress diagnosticだけ、reply 0 |
| `RF6_WRONG_ROLE_MANAGEMENT` | Endpoint cancel、Controller event resume/discard | transaction lookup前に`NINLIL_E_UNSUPPORTED`、result invalid/zero、state/spool/ledger change 0 |
| `RF7_WRONG_OBJECT_OR_MISSING` | Controllerがexisting EventFactをcancel、Endpoint event APIがexisting DesiredStateを操作、正しいroleでunknown/retention-cleaned ID | cancelは`NINLIL_E_UNSUPPORTED`/zero、event APIは`NINLIL_OK + NOT_EVENT_FACT + EVENT_FACT_IMMUTABLE`、missingは`NINLIL_E_NOT_FOUND`/zero |
| `RF8_REREGISTER_IDENTITY` | same namespace/service/revisionを、別addressのcallbacks structだが全contract/local application/function/user value exactで再登録。その後各1 fieldだけvalid変更 | exact再登録は最初と同じservice pointer、allocation/capacity/high-water/copy/order変化0。Valid mismatchは`NINLIL_E_CONFLICT`/service NULL、既存state不変。Invalid callback shapeはlookup前INVALID_ARGUMENT |
| `RF9_ENDPOINT_EVENT_CAPABILITY` | Endpoint runtime event capacity 0/0でEvent sender登録、count>0/bytes<2,560でcreate、valid count/bytesで登録 | 0/0 createは成功するがregisterは`NINLIL_E_UNSUPPORTED`/service NULL/capacity不変。Insufficient bytesはcreate INVALID_ARGUMENT。Valid profileだけ登録成功 |
| `RF10_EVIDENCE_MASK` | 両familyで4 known stage bitの全15 non-empty subset、empty、bit0 NONE、各reserved bitを登録 | 15 subsetは他contractがvalidなら成功。Empty/NONE/reservedは`NINLIL_E_INVALID_ARGUMENT`。Submissionはmask内exactly 1 non-zero stageだけ許し、advertiseだけでReceipt生成0 |

RF6/RF7はvalidation precedenceも検査します。Malformed ABI/null/headerはroleより先に`INVALID_ARGUMENT`、wrong roleはlookupより先、正しいroleだけがmissing/wrong-family semanticへ進みます。RF8はcallbacks struct pointer identityを比較せず、その中のfunction/user pointer **value**を比較します。RF10のunsupported required evidenceは`NINLIL_OK + SUBMISSION_REJECTED / NINLIL_REASON_EVIDENCE_UNSUPPORTED`で、maskにstageがあるだけではsemantic evidence成立にしません。

Service registry/restart vectors:

| Vector | Setup / operation | Required result |
| --- | --- | --- |
| `SV1_FIRST_DURABLE_REGISTER` | clean RuntimeでC1/E1 serviceをfirst register、各Storage failure/unknown | Semantic registry + SERVICE used/high-waterを1 FULL commit後だけhandle publish。Failureはhandle/callback保持0、unknownはreopen後all-or-none |
| `SV2_RECREATE_ATTACH` | register後destroy/recreate、別address/function/user valueのvalid callbacksでsame semantic service attach | Stage 5でSERVICE usedを復元、attach前handle0。Attachはnew pointer値を受理しdurable write/used/high-water増加0 |
| `SV3_UNATTACHED_PAUSE` | pending sender transaction、INBOX_COMMITTED Delivery、RECOVERY_REQUIRED、cached replyを作ってrecreateし、attach前にstep | send/callback/reconcile/reply 0、step work counter0。Valid inboundはcapacity内でdurable copy可だがpositive reply0。Exact attachでimmediate wake後だけ再開 |
| `SV4_REVISION_ISOLATION` | old revision pending中にnew valid revisionだけregister、same revision semantic mismatchも実行 | New revisionは別SERVICE slotでold pendingを受けない。Oldはunattached pause。Same-key mismatchはCONFLICT、state/capacity不変 |
| `SV5_INGRESS_RESTART_ACCOUNTING` | receive/copy FULL commit後reducer前crash | INGRESS used/message/sequenceをrestartで復元し、exactly once reduce/drop FULL commitでrelease。Step resetだけのused=0化なし |

### Public reason reachability vectors

12章のpublic reason registryのうち次のexact 9 symbolは数値ABI/default-guidance metadataだけを予約し、M1a public outputではgenerated 0です。

```text
NINLIL_REASON_UNSUPPORTED_FAMILY
NINLIL_REASON_UNSUPPORTED_SELECTOR
NINLIL_REASON_INVALID_CONTENT_DIGEST
NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID
NINLIL_REASON_MODIFICATION_REQUIRED
NINLIL_REASON_EVENT_RECEIPT_TIMEOUT
NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT
NINLIL_REASON_BEARER_UNAVAILABLE
NINLIL_REASON_CAPACITY_UNAVAILABLE
```

| Vector | Trigger | Required observable result |
| --- | --- | --- |
| `RZ1_FAMILY` | named reserved family / registry外numeric family | service registration `NINLIL_E_UNSUPPORTED` / `NINLIL_E_INVALID_ARGUMENT`。reason outputを生成するcallへ進まない |
| `RZ2_SELECTOR` | selector相当を要求 | ABI 0.1では表現不能。unknown tailをignoreし、reason `UNSUPPORTED_SELECTOR`を生成しない |
| `RZ3_DIGEST` | payloadとcaller content digestを不一致にする | API `NINLIL_E_INVALID_ARGUMENT`、Submission result INVALID/zero。reason `INVALID_CONTENT_DIGEST`を返さない |
| `RZ4_ATTEMPT_TIMEOUT_DESCRIPTOR` | attempt Receipt timeout descriptorをrange外にする | service registration `NINLIL_E_INVALID_ARGUMENT`、service NULL。reason outputなし |
| `RZ5_MODIFICATION` | counter-offer/modification相当 | M1a admissionはcounter-offerを生成せず、reason `MODIFICATION_REQUIRED`を生成しない。well-formed `offer_accept`だけがAPI `NINLIL_E_UNSUPPORTED` |
| `RZ6_AUTH_PROVIDER_DOMAIN` | origin provider temporary / permanent / invalid decision | temporaryはAPI WOULD_BLOCKでhealth cause 0。Permanent/invalidはAPI DEGRADED + Submission INVALID/reason NONEで、Runtime healthへreachable `GRANT_PROVIDER_UNAVAILABLE`をadd |
| `RZ7_EVENT_TIMEOUT` | Event attempt Receipt timeout後、cycle継続可能 | attempt observationへtimeoutを記録し、次attempt/cycle reducerを実行。public reason `EVENT_RECEIPT_TIMEOUT`を生成しない |
| `RZ8_EVENT_PARK_CAUSE` | transient-cycle exhaustion / Bearer unavailable / capacity unavailableによりEventをpark | detailは対応する`ninlil_event_park_cause_t`、public PARKED reasonは常に`NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED`。3つの同名reasonを生成しない |
| `RZ9_SURFACE_SCAN` | Submission result、transaction/target snapshot、step health、event management resultを全reachable transitionで収集 | 上記9 reasonの出現0。Provider permanent/invalid pathだけhealth reason `GRANT_PROVIDER_UNAVAILABLE`がreachableで、Submission reasonはNONE。`NINLIL_HEALTH_FATAL`も出現0 |
| `RZ10_REGISTRY_MIRROR` | 12章registryとmachine-readable YAMLを比較 | symbol/value、reserved value 67、generated-zero exact set 9件、default-guidance全54 symbolのexactly-one membershipが一致。`GRANT_PROVIDER_UNAVAILABLE` guidanceはOPERATOR_ACTION |

`NINLIL_REASON_STALE_AVAILABILITY_EPOCH`はgenerated-zero setではなく、AV1のreachable stale-epoch pathでexact value 77を生成します。旧symbol名をsource、test、fixture、生成物へ残しません。Generated-zero symbolを将来reachableにする変更はmilestone/ABI更新とYAML set変更を同じ変更へ含めます。

### ABI representability boundary vectors

M1a ABIにはselector、caller scheduled/not-before、supersede/replace、fragment/attachmentのfield/APIがありません。これらは「受け取って拒否するoperation」ではなく、callerが表現できないcapabilityです。

| Vector | Input / inspection | Required result |
| --- | --- | --- |
| `U1_UNKNOWN_TAIL_IGNORED` | valid base Submissionの`struct_size`を大きくし、unknown tailを4種類の要求に似たnon-zero patternで埋める | Coreはknown prefixだけを読み、baselineと同じresult/state/digest。tail mutationで結果を変えない |
| `U2_NO_FALSE_UNSUPPORTED` | selector/scheduled/supersede/fragmentごとにpublic headerとexported symbolを検査 | callable field/API 0。存在しない要求について`NINLIL_E_UNSUPPORTED`を返せたと主張しない |
| `U3_RESERVED_RESULTS_STAY_ZERO` | 全M1a admission/reducer scenarioを走査 | `ADMITTED_SCHEDULED_RESERVED`、counter-offer、`OUTCOME_SUPERSEDED_RESERVED`を生成しない |
| `U4_NEW_ABI_REQUIRED` | 将来の各機能を設計レビューへ入力 | new field/API、ABI/capability negotiation、canonical/storage/reducer migrationが定義されるまでM1aへ追加不可 |

`offer_accept()`、named reserved family、atomic application storage participant等の**表現可能な**unsupported operationとは区別します。Unknown tailを機能検出や要求の拒否へ使わず、ASan/guard-page testでknown `struct_size`境界より後をreadしないことを検査します。

### Origin authorization provider contract

EventFact local admissionは12章の`ninlil_origin_authorization_ops_t.evaluate`を必ず通ります。M1a providerはTEST専用ですが、Core内の`if (fixture)` shortcutで代替してはなりません。

- Coreはschema/length/content digestの構文検査後、resource reservation前に`evaluate`を1回呼びます。
- request viewはcall中borrowedです。providerはpointerを保存しません。
- requestはenvironment、`source.runtime_id/application_instance_id/local_identity`、target、service/schema/family、event ID、payload length、現在時刻、現在のactive spool count/bytes、current rate-window countを完全にbindingします。Origin device/installation/site/epochsは`request.source.local_identity`だけを正本とし、重複fieldを作りません。
- providerは12章のdecisionへallow、reason、grant ID/revision、valid-from/expiry、max payload、max active spool count/bytes、rate window/count、retry-cycle attemptsを全て設定します。
- normal denyは`ORIGIN_AUTH_OK + allowed=0`とreasonで返します。Provider temporary failureはAPI `NINLIL_E_WOULD_BLOCK`、permanent failureまたはinvalid/partial decisionはAPI `NINLIL_E_DEGRADED`です。Uncertain clockをproviderが正常判定できた場合はallowed=0 / `NINLIL_REASON_CLOCK_UNCERTAIN`、clock sample自体を取得できない場合はClock port mappingを使用します。
- `allow`でもCoreはdecisionの各limitとRuntime/descriptor limitの小さい方を再検査します。Provider decisionはstorage/queue reservationではありません。
- allow decision snapshotはgrant ID/revision、評価時刻、全binding/limit、event ID、content digestとともにEventFact admissionの1つの`FULL` transactionへ保存します。commit前に`ADMITTED`を返しません。
- grant ID/revisionはauthorization evidenceであり、canonical submission digestに含めません。grant更新・再発行で同じlogical EventFact/idempotency keyのdigestを変えてはなりません。
- grant expiry/revocationは新規admissionを止めます。既にadmittedされたEventFactのownership/spoolを消しません。

### Synthetic origin grant

Grant `7000...0001`は次へbindingします。

- environment=`TEST`
- provider/issuer=`80000000000000000000000000000001`、provider revision=`1`
- grant revision=`1`
- G1 decision digest=`SHA-256(1):3b3e9cae32f01600e4a0553339f978744f87b0af03506c1db1d484c2a2b63c93`
- decision clock epoch=`a0000000000000000000000000000001`（evaluated/valid-from/expires共通）
- subject device=`4000...0001`、application=`6000...0001`
- site=`1000...0001`、membership epoch=`1`
- service=`org.ninlil.examples/durable-event`、family=`EventFact`
- schema major=`1`、payload maximum=`1024`
- origin authority=`ORIGIN_WITH_GRANT`
- valid interval=`0 <= admission_time_ms < 86,400,000`
- max payload bytes=`1024`
- max active origin events=`32`、max active spool bytes=`32,768`

G1のdecision digestはfixture manifestが供給するopaqueなprovider-owned定数です。M1aはdecision digestのpreimageやcanonical encoderを定義しません。Coreとfixture testはalgorithm、32-byte値のexact copy/binding、non-zeroだけを検査し、逆算や再計算を行いません。
- rate window=`10,000ms`、max admissions/window=`8`
- retry cycle attempts=`8`

これはTEST providerがfixture IDと全bindingの完全一致で受理するsynthetic recordです。署名済みproduction Traffic Grantではありません。expiryは新規local admissionだけを止め、既にadmittedされたEventFactのownership、spool、retry、Receipt待ちを消しません。

`active_spool_bytes`はrequired Receipt未達のlive EventFactに属するportable `EVENT_SPOOL_BYTES used + reserved`の和で、各Eventはexactly `payload.length + 2,560`です。Attempt/summary、Storage key/index/padding等のphysical overheadとterminal後のretained audit slotはactive grant inputへ足さず、Storage/public capacityの各規則で別に管理します。Rate windowは`floor(now_ms / 10,000)`で識別し、admission count更新はEventFact admissionと同じ`FULL` transactionです。

Decision vectors:

| Vector | Input差分 | Decision |
| --- | --- | --- |
| `G1_ALLOW` | time=0、fixture binding、payload=10、active count/bytes=0/0、window count=0 | allow、reason=`NINLIL_REASON_NONE`、上記grant snapshot、`retry_delay_ms=0` |
| `G2_EXPIRED` | time=86,400,000、他はG1 | REJECTED、reason=`NINLIL_REASON_GRANT_EXPIRED`、guidance=`NINLIL_RETRY_OPERATOR_ACTION`、`retry_delay_ms=0` |
| `G3_MISMATCH` | membership epoch=2、他はG1 | REJECTED、reason=`NINLIL_REASON_GRANT_INVALID`、guidance=`NINLIL_RETRY_OPERATOR_ACTION`、`retry_delay_ms=0`。近いgrantをfallbackしない |
| `G4_COUNT_LIMIT` | active spool count=32、他はG1 | REJECTED、reason=`NINLIL_REASON_GRANT_LIMIT_EXCEEDED`、guidance=`NINLIL_RETRY_SAME_AFTER`、`retry_delay_ms=1,000` |
| `G5_BYTE_LIMIT` | active spool count/portable bytes=11/30,199、payload=10（new exact cost=2,570）、他はG1 | checked total=32,769でREJECTED、reason=`NINLIL_REASON_GRANT_LIMIT_EXCEEDED`、guidance=`NINLIL_RETRY_SAME_AFTER`、`retry_delay_ms=1,000` |
| `G6_RATE_LIMIT` | current window count=8、他はG1 | REJECTED、reason=`NINLIL_REASON_RATE_EXHAUSTED`、guidance=`NINLIL_RETRY_SAME_AFTER`、`retry_delay_ms=10,000` |
| `G7_PROVIDER_TEMP` | provider status=`NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE` | API `NINLIL_E_WOULD_BLOCK`、out kind=`NINLIL_SUBMISSION_INVALID`、reason/assurance zero、health cause 0 |
| `G8_PROVIDER_PERM` | provider status=`NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE` | API `NINLIL_E_DEGRADED`、out kind=`NINLIL_SUBMISSION_INVALID`、reason/assurance zero、health DEGRADED / `GRANT_PROVIDER_UNAVAILABLE` |
| `G9_INVALID_DECISION` | status=OK/allowed=1だがdecision digest=zero | API `NINLIL_E_DEGRADED`、out kind=`NINLIL_SUBMISSION_INVALID`/reason NONE、health DEGRADED / `GRANT_PROVIDER_UNAVAILABLE`。grant-invalid rejectionへ偽装しない |

G1〜G6のdecision clock epochはrequest `now.clock_epoch_id`とexact matchします。G2〜G6のnormal denyは`allowed=0`、non-zero provider ID/revision/decision digest、exact clock epoch/evaluated-at、表のreason/guidance/delayを返します。Grant ID/revision、valid-from/expires、全grant/limit fieldはzeroです。各fieldを1つpoisonしたvariantはnormal rejectionでなくG9 provider contract failureです。G7〜G9はSubmission rejection metricへ数えません。

Provider failure/deny時、NinlilはEventFactを所有せずspool recordを作りません。Applicationは同じevent ID/idempotency keyを保持し、API statusまたはSubmission reasonに従いproductのlocal fail-safeを実行します。

### Virtual permit fixture

Virtual issuerのpermit sequenceは1から始め、restartを跨いでharnessが保持します。まず12章`ninlil_tx_request_t`からrequest digestを作ります。

```text
request_digest = SHA-256(
    ASCII("ninlil-tx-request-v1")
    || transaction_id[16]
    || attempt_id[16]
    || message_kind_u32_big_endian
    || logical_bytes_u32_big_endian
    || content_digest_algorithm_u16_big_endian
    || content_digest_bytes[32])
```

permit IDは次のSHA-256先頭16 bytesです。

```text
SHA-256(
    ASCII("ninlil-virtual-permit-v1")
    || issuer_id[16]
    || attempt_id[16]
    || request_digest[32]
    || clock_epoch_id[16]
    || expires_at_ms_u64_big_endian
    || sequence_u64_big_endian)
```

Fixture permitはclock epoch=`a000...0001`のacquire sample時刻から使用可能で、public `expires_at_ms`はchecked(acquire時刻+1,000)です。caller submissionのnot-beforeとは無関係です。transaction、attempt、kind、content digest、logical bytes、clock epochのどれかが変われば別permitが必要です。

C1/E1を別scenario reset、issuer sequence=1、acquire=0、expiry=1,000、message kind APPLICATION=`1`として、permit goldenは次です。

| Scenario | Transaction / attempt | Logical bytes | Request digest | Permit ID (SHA-256 first 16) |
| --- | --- | ---: | --- | --- |
| C1 | `0d5382f07b9c59639f7c1957ae22fea7` / `5dd9578bd99d35ff819efba06edcb33e` | 511 | `fa5dbaf1125464f065e8a0b1875941da438411b8c796548b5409f62e2b5141cf` | `a82ca19b607f15a81ab5984de23aec7a` |
| E1 | `a0726cd8b13d4cab041a06a5fce92ca4` / `a8c780783f852e11cb4fdd5188d44ffc` | 510 | `2b3ebcf9b4606ecfa80b63e13f2945be6615f574dd01ae86133ee137e27089d9` | `8cae0f2e73895edf41b8bba899852078` |

Permit golden testはrequest digestとpermit IDを独立実装で再計算します。C struct bytes、host endian、old envelope size 503/502を使った値を受理しません。

Permit vectors:

| Vector | Condition | Result |
| --- | --- | --- |
| `P1_VALID_LAST_MS` | acquire=0、epoch一致、first send at999 | accepted、permit consumed |
| `P2_EXCLUSIVE_EXPIRY` | acquire=0、first send at1000 | `NINLIL_BEARER_DENIED`、enqueue 0 |
| `P3_EPOCH_MISMATCH` | permit epoch=`a000...0001`、current=`a000...0002` | `NINLIL_BEARER_DENIED` |
| `P4_REUSE` | P1成功後に同permitで再send | `NINLIL_BEARER_DENIED` |
| `P5_QUEUE_FULL` | valid permit、duplicate expansion込みでqueue full | `NINLIL_BEARER_WOULD_BLOCK`、permit未消費。Coreは`release_unused`し、再試行はfresh permitだけ |

Tx Gate reducer vectorsはout permitをpoisonしてから各callを行い、Application Command、Application Event、prepared CANCEL_REQUEST、cached reverse Receiptの4 message classを全て検査します。

| Vector | Acquire return | Exact result |
| --- | --- | --- |
| `TG1_OK_VALID` | OK + exact request/clock/expiry binding | そのpermitでだけ次のpre-send/sendへ進む。別attempt/kind/digest/sizeへの流用0 |
| `TG2_TEMPORARY` | TEMPORARY + zero permit | Bearer send 0。Command/Eventはattempt消費済みfixed backoff、Event 8thだけCYCLE_EXHAUSTED park。Cancel/reverseはsame prepared/cached messageを保持しfixed backoff後fresh acquire |
| `TG3_DENIED` | DENIED + zero permit | Command FAILED_DEFINITIVE/APPLICATION_FAILED、Event APPLICATION_REMEDIATION park、cancel send gate closed/PENDING、reverse automatic send closed。Health cause 0 |
| `TG4_CONTRACT_FENCE` | unknown status、non-OK+non-zero、OK+partial/mismatch/expiredを各1-field | TG3のstate + Runtime DEGRADED/OUTCOME_UNKNOWN、Bearer send 0。OK+non-zero permitだけrelease_unused exactly 1 |

Actual Bearer Application sendは次のexhaustive vectorを使います。全variantでsend resultをpoisonし、permit release/consumptionも照合します。

| Vector | Status/output variants | Required family projection |
| --- | --- | --- |
| `BS1_COMMAND_SEND_MATRIX` | OK+ACCEPTED、OK+DURABLE_CUSTODY、LOST_UNKNOWN、WOULD_BLOCK、UNAVAILABLE、DENIED、CORRUPT、EMPTY、unknown、OK+zero/unknown kind、zero/regressed epoch | accepted/unknownはEFFECT_POSSIBLE、WOULD/UNAVAILABLEはNO_EFFECT fixed-backoff、DENIEDはFAILED_DEFINITIVE、corrupt/invalidはEFFECT_POSSIBLE + DEGRADED。12章permit rule exact |
| `BS2_EVENT_SEND_MATRIX` | BS1と同じ | accepted/unknown/corruptはAWAITING_RECEIPT（corruptだけDEGRADED）、WOULD/UNAVAILABLEはattempt countを戻さずimmediate BEARER_UNAVAILABLE park、DENIEDはAPPLICATION_REMEDIATION park |
| `BS3_EVENT_CAPACITY_PARK` | valid CAPACITY_EXHAUSTED/NO_EFFECT Disposition、local admission capacity rejection、step budget exhaustion | 最初だけCAPACITY_UNAVAILABLE park。後2つはpark/cause mutation 0 |
| `BS4_REVERSE_SEND_MATRIX` | cached Receipt/Disposition/Custody/CancelResultで全status/output shape | WOULD/UNAVAILABLEだけsame cached messageのfixed-backoff retry、DENIEDはautomatic close、accepted/unknownはautomatic duplicate 0、corrupt/invalidはclose+DEGRADED。Application callback/result commit追加0 |
| `BS5_RECEIVE_STATUS_MATRIX` | receive_nextのOK-valid、OK各1-field invalid、EMPTY/WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN/CORRUPT/unknown、non-OK poison | 12章output/release/first-error matrix exact。OKだけrelease exactly1、temporary/EMPTY release0、invalidからreply/callback0 |
| `BS6_STATE_STATUS_MATRIX` | stateのOK available0/1/new/exact-same/old/same-epoch-conflict、全non-OK、unknown、partial/poison | 12章shape/health/first-error exact。Valid strictly larger epochだけnamespace observation、new availableだけresume候補。New unavailableもcommit、ordered-input/owner sequence0、available0/exact-same/old/tempはresume0、same-epoch conflictはDEGRADED/state不変 |
| `BS8_CUSTODY_LIFECYCLE` | APPLICATION ingress commit前/後、cached CUSTODY send全status、sender current/old/duplicate/invalid attempt、Command/Event | Ingress FULL後だけcached reply。Senderはremote custodyを1回commitしattempt retry timerをclearするがpayload/required evidence/Outcome不変。Duplicateはrevision/state0、invalid bindingはobservationだけ。Hookとreverse observation state exact |

## Canonical Submission Encoding v1

### 目的とscope

Idempotency mappingは`source application instance + service identity(namespace + service ID)`をscopeとします。Descriptor revisionはscopeへ含めず、canonical submission digestへ含めます。同じidempotency keyでrevisionまたは内容だけを変えた再提出は`IDEMPOTENCY_CONFLICT`です。DesiredStateCommand/EventFactを含む全caller-key mappingの正本はkey length + exact raw bytesで、補助SHA-256 indexは任意です。Forced hash collisionでもraw bytesが異なれば同じkeyとして扱いません。EventFact event-ID mappingは、この同じraw keyをvalue側にもbindingする追加indexです。

Encoding名は`canonical-submission-v1`です。これはradio wire、storage record、payload schemaではありません。

### Scalar rule

- integerはunsigned big-endianです。
- IDは16 bytesを表のbyte orderのまま置きます。
- text IDは1〜63 bytesのASCII exact bytesで、NUL終端をencodeしません。namespaceは`[a-z0-9][a-z0-9.-]*`、service/schema IDは`[a-z0-9][a-z0-9._-]*`です。
- checked lengthを使用し、host struct padding、enum size、map orderを使用しません。
- public enumは12章の固定`uint32_t`値をu32でencodeします。M1a familyはEventFact=`1`、DesiredStateCommand=`2`です。
- digestはalgorithm u16と32 digest bytesです。`ninlil_digest256_t.reserved_zero`はsemantic valueでないためencodeしません。M1a SHA-256 algorithmは`1`です。
- `NINLIL_NO_DEADLINE`は`0xffffffffffffffff`です。

### Top-level encoding

```text
magic = ASCII "NCS1"
field = tag:u8 || length:u32 big-endian || value[length]
```

tag `0x01`〜`0x10`を昇順に各1回だけ出力します。unknown、duplicate、欠落tagはinvalidです。

| Tag | Field | Value encoding |
| ---: | --- | --- |
| `01` | namespace | exact ASCII bytes |
| `02` | service ID | exact ASCII bytes |
| `03` | descriptor revision | u64 |
| `04` | descriptor digest | algorithm u16 + 32 bytes |
| `05` | source application instance | 16 bytes |
| `06` | family | public family u32 |
| `07` | schema ID | exact ASCII bytes |
| `08` | schema major | u16 |
| `09` | schema minor | u16 |
| `0a` | concrete target roster | 下記 |
| `0b` | effect deadline ms | u64 relative、またはNO_DEADLINE |
| `0c` | evidence grace ms | u64 |
| `0d` | required evidence | public evidence u32 |
| `0e` | family metadata | 下記 |
| `0f` | content digest | algorithm u16 + 32 bytes |
| `10` | payload length | u32 |

Namespace/serviceはidempotency scopeにも存在しますが、standalone golden/debug artifactを自己記述的にし、scope/digest取り違えを検出するためbyte列にも含めます。

次は含めません。

- idempotency key: scope内mappingのlookup keyでありlogical contentではない
- source Runtime IDとsource local identity: idempotency scope外であり、application instanceの配置・attachment snapshotをauthorization/admission evidenceと分離する
- transaction/attempt ID: admission/retry後に生成される
- admission time/clock epoch、absolute deadline、internal retry-not-before: reducer stateでありcaller submissionではない
- origin grant ID/revision: authorization evidenceでありgrant更新でlogical eventを変えない
- apply contract: immutable ServiceDescriptor fieldであり、tag `04`のdescriptor digestがbindingする
- raw payload: tag `0f` content digestとtag `10` lengthでbindingする

Descriptorのapply/custody contract、direction、authority、schema、limitを変えた場合、同じdescriptor digestを再利用してはなりません。

### Target roster

```text
target_count                     u32
repeated fixed 100-byte records:
  target_runtime_id              16 bytes
  target_application_instance   16 bytes
  target_flags                   u32
  device_id                      16 bytes; absentならall-zero
  installation_id                16 bytes; absentならall-zero
  site_domain_id                 16 bytes; absentならall-zero
  binding_epoch                  u64
  membership_epoch               u64
```

`target_flags`は12章`NINLIL_TARGET_HAS_DEVICE / INSTALLATION / SITE`のbit値です。flagなしfieldはzero placeholder、flagありrequired IDはnon-zeroでなければなりません。未知flag、non-zero `reserved_zero`、flagとplaceholderの不一致はcanonical encode前にrejectします。

Recordをrecord全100 bytesのunsigned lexicographic orderでsortします。完全一致duplicateはvalidation errorです。M1aは`target_count=1`だけをadmitしますが、encoder自体は同じcanonical sortを実装します。required evidenceはtop-level tag `0d`だけに存在し、target recordへ重複encodeしません。

### Family metadata

DesiredStateCommand:

```text
generation          u64
```

EventFact:

```text
event_id            16 bytes
```

M1a Submission ABIにはreplace keyがなくsupersedeも未対応なので、replace keyをencodeしません。Apply contractはdescriptor digest経由でbindingします。Origin grantはauthorization snapshotへ保存しますがencodeしません。M1a EventFactはtop-level deadlineが`NINLIL_NO_DEADLINE`、evidence graceが0でなければrejectします。

### Digest

`canonical_submission_digest = SHA-256(canonical-submission-v1 bytes)`です。Digest comparisonは32 bytesすべてを比較します。Encoderは同じlogical inputから常に同じbyte列を作らなければなりません。

### EventFact intrinsic identity

EventFactはidempotency key mappingとは別に、同じidempotency scope内のdurable `event_id -> transaction_id + canonical_submission_digest + idempotency_key_length + exact raw idempotency key bytes` mappingを持ちます。Raw keyは1〜64 bytesをlengthとともにcopyし、最終同一性はlength + 全raw bytesのexact比較だけで決めます。

Implementationは`SHA-256(raw idempotency key)`を補助indexに持てますが、mappingの正本/最終比較ではありません。Auxiliary digestが一致してもlength/raw bytesが異なればconflictです。Keyはcanonical submission bytesへ追加しません。

- same event ID + same canonical digest + same idempotency keyの3条件が揃う場合だけ、同じtransactionの`NINLIL_SUBMISSION_ALREADY_ADMITTED`です。
- same event ID + same canonical digestでもidempotency keyが異なる場合は`NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT`です。bounded alias mappingを追加しません。
- same event ID + different canonical digestも`NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT`です。新event ID/keyを採番して回避してはなりません。
- key mappingとevent mappingが異なる既存transactionを指す場合もconflictで、どちらも上書きしません。
- 新規EventFactのkey mapping、event mapping、transaction、payload/spool、grant snapshotは1つの`FULL` transactionでcommitします。
- event mappingはrequired Receipt/discard前に削除せず、その後も少なくとも`required_dedup_window_ms`保持します。

Grant IDとidempotency keyをcanonical bytesへ含めない規則は維持しますが、event mappingはidempotency keyのlength + exact raw bytesをbindingします。補助SHA-256 indexは任意で、persistの必須fieldでも最終比較の正本でもありません。Exact retryで既存transactionへ収束した場合、authorizationを再評価して別transactionを作りません。

## Golden vectors

hexは改行を除いて連結します。

### Vector C1: Reliable Command

Input:

```text
namespace                 org.ninlil.examples
service                   absolute-state
descriptor revision       1
descriptor digest         1:4a36772bfa7a683c4b203da25f990bd8903f053515bfe144077283a26c8e0abd
source app                30000000000000000000000000000001
family                    DesiredStateCommand (public value 2)
schema                    absolute-state/1.0
target Runtime            41000000000000000000000000000001
target application        60000000000000000000000000000001
target flags              DEVICE | INSTALLATION | SITE = 7
target device             40000000000000000000000000000001
target installation       50000000000000000000000000000001
binding/site/member epoch 1 / 10000000000000000000000000000001 / 1
deadline/grace            5000 / 1000 ms
required evidence         APPLIED
generation                1
payload hex               010100000000000000
payload SHA-256           46f8ec5a439c92e1df8299e1a4432a7ee172d8496b5e33e0a35a7b67163371b5
```

Canonical bytes length=`367`:

```text
4e43533101000000136f72672e6e696e6c696c2e6578616d706c6573020000000e616273
6f6c7574652d737461746503000000080000000000000001040000002200014a36772bfa
7a683c4b203da25f990bd8903f053515bfe144077283a26c8e0abd050000001030000000
000000000000000000000001060000000400000002070000000e6162736f6c7574652d73
7461746508000000020001090000000200000a0000006800000001410000000000000000
000000000000016000000000000000000000000000000100000007400000000000000000
000000000000015000000000000000000000000000000110000000000000000000000000
000001000000000000000100000000000000010b0000000800000000000013880c000000
0800000000000003e80d00000004000000030e0000000800000000000000010f00000022
000146f8ec5a439c92e1df8299e1a4432a7ee172d8496b5e33e0a35a7b67163371b51000
00000400000009
```

Canonical digest:

```text
5b34535914a8d1392d84f7c5ba763b75ab986f4ae9fed200b16655b8e35a8b98
```

### Vector E1: Durable Event

Input:

```text
namespace                 org.ninlil.examples
service                   durable-event
descriptor revision       1
descriptor digest         1:f64b7c4abf5b9db38b1c9fef0f0e8c341b56caddadb291ebc5456ccbd2aa321b
source app                60000000000000000000000000000001
family                    EventFact (public value 1)
schema                    durable-event/1.0
target Runtime            21000000000000000000000000000001
target application        30000000000000000000000000000001
target flags              DEVICE | INSTALLATION | SITE = 7
target device             20000000000000000000000000000001
target installation       50000000000000000000000000000002
binding/site/member epoch 1 / 10000000000000000000000000000001 / 1
deadline/grace            NINLIL_NO_DEADLINE / 0
required evidence         DURABLY_RECORDED
event ID                  90000000000000000000000000000001
authorization             G1_ALLOW; grant ID is not encoded
payload hex               01000100000000000000
payload SHA-256           c79dfd1639cb01c6e9475beccd17d9e076ca80f62f4c5a505a1586cc7a3e9338
```

Canonical bytes length=`373`:

```text
4e43533101000000136f72672e6e696e6c696c2e6578616d706c6573020000000d647572
61626c652d6576656e740300000008000000000000000104000000220001f64b7c4abf5b
9db38b1c9fef0f0e8c341b56caddadb291ebc5456ccbd2aa321b05000000106000000000
0000000000000000000001060000000400000001070000000d64757261626c652d657665
6e7408000000020001090000000200000a00000068000000012100000000000000000000
000000000130000000000000000000000000000001000000072000000000000000000000
000000000150000000000000000000000000000002100000000000000000000000000000
01000000000000000100000000000000010b00000008ffffffffffffffff0c0000000800
000000000000000d00000004000000020e00000010900000000000000000000000000000
010f000000220001c79dfd1639cb01c6e9475beccd17d9e076ca80f62f4c5a505a1586cc
7a3e933810000000040000000a
```

Canonical digest:

```text
e19ab779c806d9c6f4a4cbd6720408384b3437e29a3a967b9cf93750290eeebb
```

### Vector E2〜E4: Event intrinsic dedup/conflict

E1のidempotency keyをlength 11 / exact ASCII `event-key-a`、E3をlength 11 / exact ASCII `event-key-b`とします。Keyはcanonical bytesに含まれません。補助index digestを使うimplementationはそれぞれ`31bd2abcfe30ce63222f787f484be24353e7f7229fcef837e7602a3b755e8096`と`5c4d37d112b23cce2d4ca9772d1114c20357ec6b16db5f4bbc83376d2494a7f9`を得ますが、result判定はraw比較です。

| Vector | Difference from E1 | Canonical/content digest | Required result |
| --- | --- | --- | --- |
| `E2_EVENT_EXACT_RETRY` | E1とevent ID/payload/key/全fieldが同じ | canonical=`e19ab779...eeebb`、content=`c79dfd16...e9338` | E1と同じtransactionの`ALREADY_ADMITTED` |
| `E3_EVENT_KEY_CONFLICT` | 同じevent ID/payload/全field、key=`event-key-b` | canonical=`e19ab779...eeebb`、content=`c79dfd16...e9338` | `IDEMPOTENCY_CONFLICT`、alias mappingなし |
| `E4_EVENT_DIGEST_CONFLICT` | 同じevent ID/key、payload sequenceだけ2 | canonical=`2a71af77a98ccd25f1965de1fa843d019e3e06f8fae96462a5571b35cb5aeb13`、content=`6c52470213bc347952f56bc8a73b687443e71a86a8d120018e6bb2dd292072dd` | `IDEMPOTENCY_CONFLICT`、既存transaction/digest不変 |

E4 payload hexは`01000200000000000000`、lengthは10です。E3はkeyだけが異なるためcanonical byte列もE1と完全一致しますが、event mappingのexact raw key不一致でconflictになります。補助index digestをtest doubleで同値に強制したE3 variantも同じconflictで、hash一致をexact key一致に格上げしません。

Golden testはencoder出力、decoder round-trip、1-bit mutation、field order、target fixed-record/flags、invalid ASCII/pattern/length、NO_DEADLINE、overflowを検査します。Multi-target sortはM1b forward-only encoder testであり、M1a admission successに数えません。C1/E1のraw payload schemaはfixture内でlittle-endianですが、canonical metadataのintegerは常にbig-endianです。

### Submission result all-field vectors

各call前にouter/nested result storageをnon-zero poisonで満たし、return後の全fieldを比較します。Zero digestはalgorithm/reserved/32 bytes全zero、zero assuranceはprofile/全flag/reserved zeroです。

| Vector | API status / kind | Required all-field result |
| --- | --- | --- |
| `SR1_API_ERROR` | content digest mismatch等 / `NINLIL_SUBMISSION_INVALID` | reason NONE、guidance NEVER、delay0、transaction/digest zero、nested assuranceはheaderを含めall-zero。Outer result headerだけcurrent |
| `SR2_NORMAL_REJECT` | target count 0またはreceiver submit / `NINLIL_OK + NINLIL_SUBMISSION_REJECTED` | exact non-zero reason/guidance/delay、transaction/digest zero、nested current header + `ASSURANCE_NONE` + flags zero |
| `SR3_CONFLICT_EXISTING` | E3/E4またはC1 key/digest conflict / `NINLIL_OK + NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT` | reason IDEMPOTENCY_CONFLICT、guidance RETRY_MODIFIED、delay0、**existing** transaction IDとexisting persisted canonical digest、nested current header + assurance none/flags zero |
| `SR4_ADMITTED` | C1/E1 first admission / `NINLIL_OK + NINLIL_SUBMISSION_ADMITTED_READY` | reason NONE、guidance NEVER、delay0、new non-zero transaction、FULL-committed canonical digest、current nested header + persisted FOUNDATION_M1A_LOCAL snapshot |
| `SR5_ALREADY` | exact duplicate / `NINLIL_OK + NINLIL_SUBMISSION_ALREADY_ADMITTED` | reason NONE、guidance NEVER、delay0、existing transaction/digest、existing persisted assurance snapshotをbyte/value同値で返す |

SR2はcanonical計算まで到達していてもdigestを公開しません。SR3はconflicting new candidate digestやzeroでなく、lookup先existing digestを返します。Rejected/conflictへpartial assuranceを返さず、API errorへnested headerを初期化しません。`NINLIL_OK + SUBMISSION_INVALID`、API error + semantic kind、admitted kind + zero ID/digestはすべてcontract failureです。

## Conformance and release gates

### M1a mandatory suites

| Requirement set | Test evidence |
| --- | --- |
| `NIN-FND-STO-001` transaction lifecycle/atomicity | in-memory modelとSQLite portで同一operation trace、FULL1でM1a durable commitは全てFULL |
| `NIN-FND-STO-002` FULL/commit unknown | committed/non-committed hidden ground truth、全named boundary crash |
| `NIN-FND-STO-003` key/prefix/capacity | binary keys、stable order、MB1〜MB8 mutable buffer/iterator pair atomicity、exact byte boundary |
| `NIN-FND-STO-004` namespace ownership | NS1〜NS9 opaque 1..255/deep-copy/open/close/deallocate/single-writer lease |
| `NIN-FND-LIF-001` Runtime create lifecycle | CR1〜CR11 9-stage order、first failure、eager Bearer、status mapping、reverse cleanup |
| `NIN-FND-LIF-002` Runtime destroy lifecycle | DR1〜DR8 precondition no-consume、DESTROYING、single active-token group、failure/unknown/recovery/cleanup |
| `NIN-FND-BER-001` typed copy/identity/custody | caller buffer mutation、duplicate/loss/reorder、custody-before/after commit |
| `NIN-FND-BER-002` virtual permit | C1/E1 request/permit golden、P1〜P5、TG1〜TG4、missing/digest/attempt mismatch paths |
| `NIN-FND-BER-003` kind/orientation/binding | 6-kind matrix、O1、O2A〜O2F、BS1〜BS8 cancel/send/receive/state/custody/all-field、field mutation |
| `NIN-FND-BER-004` availability epoch | AV1〜AV2 state revision、degradation記録、available improvementだけconsume、restart/poll stable、single consume、複数Event fan-out、capacity-domain separation |
| `NIN-FND-AUTH-001` origin authorization | G1〜G9、temporary/permanent health domain、grant snapshot atomicity、TEST外拒否 |
| `NIN-FND-ADM-001` admission quota | AQ1〜AQ10 per-service/grant/counter precedence、bounded window、inclusive boundary、atomic/restart/unknown |
| `NIN-FND-CLK-001` virtual/admission time | T0 pre-commit reference/commit-crossing、same-time order、overflow、restart、trust loss |
| `NIN-FND-CLK-002` evidence time | T1〜T4 shared/mismatch/uncertain/no-deadline vectors |
| `NIN-FND-ENT-001` entropy | cross-language block vectors、chunk rule、restart、failure |
| `NIN-FND-ENT-002` generated ID order | C1/E1 block0〜2、TXID1〜TXID3、ID1〜ID3 max-4/zero/collision/failure |
| `NIN-FND-SIM-001` replay | same fixture/script/seedを2回実行しtrace digestとpublic snapshots一致 |
| `NIN-FND-SIM-002` restart | volatile loss、durable preservation、accepted in-flight delivery可能性 |
| `NIN-FND-SIM-003` step budget | B1〜B13 exact 6-counter units、worst-case callback/send preflight、split boundary/unknown、ordinary send crash replay |
| `NIN-FND-SIM-004` next wake | W1〜W6 immediate/future/epoch/trust vectors |
| `NIN-FND-SIM-005` durable-ingress boundary | S1/S2 provider arrival、FULL ingress、management order |
| `NIN-FND-SCH-001` deterministic scheduler | SCH1〜SCH7 stable ring/cursor/fairness、ingress lane、既存owner binding、same-time order、send crash replay、SC1〜SC2 clock order、SE1 first-error、AVP1 poll、INQ1〜INQ2 ingress order/ownership |
| `NIN-FND-RET-001` retention lifecycle | RET1〜RET6 exclusive end、clock pending/rebase/overflow、attempt indexを含むatomic cleanup |
| `NIN-FND-MET-001` metrics and health | MT1〜MT7 exact triggers/reset/saturation、HL1〜HL7 active-cause priority/add/clear/restartとmethod別source key |
| `NIN-FND-QRY-001` transaction query/list | QRY1〜QRY8 origin-only stable list、QPX1〜QPX4 all-field projection、revision/unknown/exhaustion |
| `NIN-FND-ABI-001` role/family/callback matrix | RF1〜RF10 registration/reregistration/evidence mask、receiver submit、wrong-direction/role/object/missing |
| `NIN-FND-LIF-003` service restart attachment | SV1〜SV5 durable registry、recreate attach、unattached pause、revision isolation、ingress recovery |
| `NIN-FND-ABI-002` reason reachability | RZ1〜RZ10 generated-zero exact 9、provider health-only reason、value77/YAML/default guidance |
| `NIN-FND-ABI-003` representability boundary | U1〜U4 selector/scheduled/supersede/fragment absent、unknown tail ignored、新ABI requirement |
| `NIN-FND-ABI-004` Submission output | SR1〜SR5 all-field poison/zero/header/assurance/existing conflict identity matrix |
| `NIN-FND-CFG-001` Runtime config limits | RL1〜RL7 role min/max、conditional zero、cross-field、overflow、retention/reserved |
| `NIN-FND-CAP-001` Runtime resource ledger | CAP1〜CAP9 11-kind limits/order/durability/block metadata/epoch saturation/corruption、Event/evidence exact cost |
| `NIN-FND-APP-001` bounded defer | D1/D2 timeout/invalidation/reconcile、same-time complete、uint64 generation、33rd rejection |
| `NIN-FND-APP-002` callback/result contract | F1〜F5、DV1〜DV11、one-field invalid cross-product |
| `NIN-FND-APP-003` callback ownership/lifetime | CB1〜CB7 struct/user copy、out init/read gating、evidence deep-copy、borrowed views、reconcile fixed backoff |
| `NIN-FND-RTY-001` timeout/backoff | R1C/R1E/R1S/R1N、R2〜R4、family split、late Receipt、8-attempt park |
| `NIN-FND-EVT-001` manual resume ledger | M1〜M8 8-slot/pre-reservation/lookup precedence/unknown/cause guard |
| `NIN-FND-AUD-001` audited discard | A1 success/unknown/clock-uncertain/Receipt race |
| `NIN-FND-FLT-001` named hook registry | 12章§17との130-name ordered mirror一致、全hook crash、specific transition pair matrix |
| `NIN-FND-CAN-001` canonical bytes | C1/E1 byte一致、E2〜E4 event identity convergence/conflict |

Storage suiteは各operationに対し、success、invalid argument、capacity、would-block、I/O、corruption、commit unknownを到達可能にします。Fault testはrandom seedだけでなく12章§17 registryの全named hookをsystematicに走査します。

### Pull request gate

- canonical C1/E1、Event E2〜E4、entropy block/ID order、TXID1〜TXID3、ID1〜ID3
- storage FULL1/MB1〜MB8/SH1〜SH5/namespace NS1〜NS9、bearer handle BH1、create CR1〜CR11、destroy DR1〜DR8、bearer kind+orientation/O2/BS1〜BS8 send/receive/state/custody、clock/permit P1〜P5/TG1〜TG4 conformance
- role/family RF1〜RF10、service restart SV1〜SV5、reason RZ1〜RZ10、representability U1〜U4、Submission SR1〜SR5、origin authorization G1〜G9、admission quota AQ1〜AQ10、deferred D1/D2、callback CB1〜CB7/F1〜F5、Disposition DV1〜DV11
- retry R1C/R1E/R1S/R1N/R2〜R4、admission/Receipt time T0〜T4、resume M1〜M8、discard A1
- config RL1〜RL7、capacity CAP1〜CAP9、step B1〜B13、scheduler SCH1〜SCH7/SC1〜SC2/SE1/AVP1/INQ1〜INQ2、availability AV1〜AV2、management MG1〜MG5、metrics MT1〜MT7/health HL1〜HL7、wake W1〜W6、retention RET1〜RET6、same-time boundary S1/S2
- transaction query/list QRY1〜QRY8/QPX1〜QPX4、origin-only domain、all-field projection、mutation/restart/revision/unknown/exhaustion
- fixed simulator regression scenariosと100 seeds
- 130-name ordered hook mirror一致、HC1〜HC15と全named crash boundary
- same-seed replayのtrace digest一致
- ASan/UBSan、C11/C++17 header smoke、docs/example smoke
- synthetic artifactが`TEST`以外で拒否されるnegative test

### Nightly gate

- 10,000 seedsと保持済みfailure seedのreplay
- SQLite commit-unknown、full、corrupt、reopen matrix
- event queue/order、capacity exact-boundary property test
- simulator livelock/max-event test
- 07章のfuzz、TSan、migration matrix

### M3以降の追加gate

- M3: ESP-IDF portが適用可能な同じstorage/key/order/capacity/clock/entropy testを通り、power-cut HILでFULL boundaryを証明する。
- M4: real identity/membership/grant fixtureを追加し、synthetic grantがTEST artifact外へ入らないbuild/release検査を行う。
- M5: virtual permit suiteに加え、real TxPermit、nonce/replay、spy radio、対象hardware測定を行う。virtual suiteで代替しない。
- M6: KGuard Display/Leak testはgeneric conformanceに追加して実行し、置換しない。
- M7以降: 新bearer、relay、multi-parentもsame logical identity、custody、bounded accounting、deterministic fault modelを満たす。

## Foundation exit condition

本章についてM1a実装開始可能と判断できるのは、次がすべて成立したときです。

- 12章のABIだけからportを実装でき、本章以外の暗黙methodを要求しない。
- 2つの独立encoderがC1/E1のbyte列とdigestへ一致する。
- 2つのstorage implementationが同じoperation/status/capacity traceへ一致する。
- Runtime namespaceのopaque byte identity/deep-copy/close-deallocate/single-writer leaseがNS1〜NS9へ一致する。
- 11 resource entryが同じunit/limit/used/reserved/high-water/epoch traceへ一致する。
- Event spoolのpublic totalがlive中exact `payload.length + 2,560`で、attempt/summary physical overheadと分離される。
- Runtime create/destroyがCR1〜CR11/DR1〜DR8のpublish/consume boundary、atomic token recovery、reverse cleanupへ一致する。
- 同じbudget/input/Port scriptからB1〜B13のcounterとnext durable boundary、MT/HLのmetrics/health snapshotが一致する。
- commit unknownの両ground truthからidempotency mappingへ安全に収束する。
- same seed/scriptから同じevent order、trace digest、public final snapshotを得る。
- C1/E1 scenario resetでmetrics/transaction/attempt IDがblock0/1/2 goldenへ一致する。
- crash/restart後にfalse success、EventFact silent loss、terminal reversal、permit bypassが0である。
- Remote cancelがsingle prepareを守り、definite WOULD_BLOCK以外またはuncertain crash後にrequestを再invokeしない。
- deferred timeout後のlate completionがstateを変えず、reconcile完了までdelivery resourceを解放しない。
- `PARKED_RETRY` EventFactがrestartだけで再送されず、fresh Bearer availability epoch + `available=1`または一意resumeでだけ再開する。
- TEST fixtureからproduction security、radio性能、法規適合を主張していない。
