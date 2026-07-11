# 13. Foundation M1a State Machine

状態: Normative pre-alpha
対象: ADR-0001で定めたFoundation M1a reducer
適用runtime role: CONTROLLER、ENDPOINT
検証環境: Runtime外部のdeterministic simulator harness

## 目的

本章は、Foundation M1aの状態遷移を、実装者が独自判断せずreducerとtest vectorへ変換できる粒度で固定します。

本章が詳細化する範囲は次です。

- admission assuranceとlocal reservation
- Submission、Target、Transaction、Endpoint Delivery、EventFact spool
- reducer input、guard、next state、reason code
- 同一時刻の競合順序
- DesiredStateCommandのeffect deadlineとevidence grace
- EventFactのno-deadline、retry cycle、park、resume、discard
- cancel、Receipt、Delivery Disposition、retry exhaustion、storage error
- late evidence
- crash recovery
- M1bで追加するALL_TARGETS集約の不変条件

Security envelope、wire、radio MAC、real route、production identity、法規profileの正しさは本章の対象外です。

## 仕様上の位置付け

本章は[ADR-0001](adr/0001-project-boundary-and-first-release.md)のM1a決定を実行可能にする詳細仕様です。M1a reducerについては、本章が[02-application-contracts.md](02-application-contracts.md)、[04-runtime-api-and-storage.md](04-runtime-api-and-storage.md)、[08-foundation-release.md](08-foundation-release.md)を詳細化します。

矛盾が見つかった場合は、実装で推測して埋めず、先に仕様を更新します。

## 規範語

- MUST / 必須: M1a準拠実装が必ず満たす。
- MUST NOT / 禁止: M1a準拠実装が行ってはならない。
- SHOULD / 推奨: 逸脱理由と互換性影響を記録した場合だけ外せる。
- MAY / 任意: profileまたはportが選択できる。

状態名とreason codeは英大文字を規範表記とします。日本語は説明であり、operator向け表示文言ではありません。

## M1aの固定scope

### 実装必須

- concrete target 1件だけのDesiredStateCommand
- Controllerをconcrete target 1件とするEventFact
- CONTROLLER、ENDPOINT
- durable admission
- idempotency
- bounded local reservation
- Receipt、Delivery Disposition、Outcome
- cancel
- DesiredStateCommandのretry budget
- EventFactの8-attempt retry cycleとPARKED_RETRY
- deadline、evidence grace、late evidence
- endpoint result cache
- copyable deferred delivery token、bounded timeout、reconcile
- EventFact origin spool
- POSIX durable storage
- 外部deterministic simulator harnessから駆動するsimulated bearer port
- named crash recovery

### M1aで未対応

- target selector、caller scheduled / not-before field。ABI 0.1 known structにfield自体がなく、future tailはignoreするためM1a reducer inputとして検出不能
- target_countが1以外のSubmission
- group transactionとALL_TARGETSの実装
- counter-offerとoffer_accept
- automatic supersede
- real Attachment、Route Lease、Traffic Grant
- Cell Agent、real bearer、radio、airtime reservation
- physical TX compliance
- remote capacityの同期予約

未対応機能は対応済みのように見せてはなりません。

- target_countが1以外のSubmissionはREJECTED、reasonはNINLIL_REASON_TARGET_COUNT_UNSUPPORTEDです。
- M1a Submissionにはcounter-offer / modification-required guard自体がなく、COUNTER_OFFEREDと対応reasonを生成しません。
- ninlil_offer_acceptはM1a buildではNINLIL_E_UNSUPPORTEDです。

M1a EventFactは期限付き配送を受け付けません。

- effect_deadline_msはuint64_t最大値のNINLIL_NO_DEADLINEでなければなりません。
- evidence_grace_msは0でなければなりません。
- ServiceDescriptorのattempt_receipt_timeout_msは1〜`NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS`、retry_backoff_msは1〜`NINLIL_M1A_MAX_RETRY_BACKOFF_MS`でなければなりません。
- finite deadlineを持つEventFactはREJECTED、reasonはNINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTEDです。
- 1 retry cycleはNINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE、すなわち8 attemptsです。
- current cycleのattempt detailは8件、recent cycle summaryはNINLIL_M1A_EVENT_RETRY_SUMMARY_SLOTS、すなわち4件です。
- 8 attemptsを使い切ってもEventFact transactionをterminalにせず、PARKED_RETRYで保持します。

## 外部に約束する範囲

### M1aが約束すること

M1aのADMITTEDは、Admission Authorityのlocal durable storage内で、次の処理がatomicに完了したことだけを意味します。

1. SubmissionとServiceDescriptor revisionを検証した。
2. concrete target 1件を固定した。
3. transaction IDを割り当てた。
4. storage namespaceのnext transaction sequenceをchecked割当てし、transactionのimmutable `transaction_sequence`、target、idempotency mapping、local reservation、最初のoutboxまたはspool itemと同じFULL transactionでcommitした。
5. local retry、record、queueの上限を超えないことを確認した。
6. Runtimeが本章の規則でterminal Outcomeを作り、query可能にする責任を引き受けた。

### M1aが約束しないこと

ADMITTEDは次を意味しません。

- remote endpointが現在生存している。
- remote inboxやresult cacheが空いている。
- route、receive window、bearer capacityが確保済みである。
- radio送信、LBT、airtime、法規判定が成功する。
- deadlineまでにrequired evidenceへ到達する。
- application effectがexactly-onceになる。
- storage deviceの物理破壊まで含めてdataが失われない。

EventFactのADMITTEDは、required Receiptまたは監査付きexplicit discardまで有限時間で必ず終わることを意味しません。PARKED_RETRYはNinlilがpayloadを保持したまま、fresh Bearer availability epoch + `available=1`またはoperator resumeを待っているactive stateです。

M1aのdurabilityは、採用したstorage portが宣言するpower-loss / crash fault profile内の保証です。保証対象外の媒体破壊や実装外故障を、silentに保証対象へ含めてはなりません。

## Admission Assurance

### 表現

Admission resultは、result kindだけでなく、次を含むadmission assurance snapshotを返さなければなりません。

| Field | M1aの値 | 意味 |
| --- | --- | --- |
| assurance_profile | FOUNDATION_M1A_LOCAL | M1a local-only assurance |
| submission_validated | true | family、schema、length、deadline、evidenceを検査済み |
| target_roster_fixed | true | concrete target 1件をcommit済み |
| descriptor_snapshot_fixed | true | immutable descriptor revisionを固定済み |
| local_journal_committed | true | transactionのlocal durable commit済み |
| local_capacity_reserved | true |下記local reservationを確保済み |
| idempotency_mapping_committed | true | caller keyからtransactionへのmappingをcommit済み |
| origin_grant_snapshot_committed | EventFactだけtrue | TEST providerのALLOW decisionとlimitsをcommit済み |
| remote_capacity_reserved | false | remote storageは予約していない |
| route_feasibility_verified | false | real routeはM1a対象外 |
| receive_window_reserved | false | sleepy windowはM1a対象外 |
| bearer_capacity_reserved | false | harness上のsimulated deliveryは物理容量保証ではない |
| airtime_reserved | false | airtimeはM1a対象外 |
| compliance_permit_issued | false | physical TxPermitはM1a対象外 |

falseのfieldを省略してtrueのように見せてはなりません。将来profileでtrueにする場合は、そのresource ownerによるreservation evidenceが必要です。

### Admission result

M1aは次だけを返します。

| Result | 所有権 |
| --- | --- |
| ADMITTED_READY | Ninlilが所有する。local dispatch queueへ投入可能 |
| ALREADY_ADMITTED | Ninlilが所有済みの同一transactionを返す |
| REJECTED | Ninlilは所有しない |
| IDEMPOTENCY_CONFLICT | Ninlilは新しい要求を所有しない |

ADMITTED_SCHEDULED、COUNTER_OFFERED、NINLIL_REASON_UNSUPPORTED_SELECTORは後続ABI / release用の予約値です。M1a reducer / fixture / public resultが生成してはなりません。M1a Submissionにselectorもcaller指定scheduled / not-beforeもなく、larger future `struct_size` tailはignoreするため「selectorあり」と推測してREJECTEDを返しません。M1aでreachableな複数target guardは`target_count == 1`だけです。

Storage commitの成否を確定できない場合、REJECTEDを返してはなりません。API invocationをNINLIL_E_STORAGE_COMMIT_UNKNOWNとして失敗させ、callerは同じidempotency keyでqueryまたは再提出します。

## Local Reservation

### Controller admission

DesiredStateCommandのadmissionは、次を1つのstorage transactionでcommitします。

- transaction record 1件
- storage namespace sequence counterのchecked incrementとimmutable transaction_sequence 1件
- concrete target record 1件
- self-contained ServiceIdentity valueとimmutable ServiceDescriptor snapshot binding 1件
- idempotency mapping 1件
- local outbox entry 1件
- DesiredStateはremote cancel attempt / record / outbox metadata 1件。Logical cancelはtransactionあたりexactly 1で、unusedでもadmission時にcapacityをreserve
- payload bytes
- attempts_per_targetで宣言したattempt record budget
- raw evidence detail最大8件
- evidence summary record 1件
- terminal Outcomeとlate evidence retentionのrecord budget

Endpointのinbox、dedup、result cacheはControllerのlocal reservationに含みません。Simulator fixtureがremote capacityを宣言していても、それはtest前提であり、admission assuranceのremote_capacity_reservedをtrueにしてはなりません。

### Endpoint EventFact admission

EventFactのorigin admissionは、次を1つのstorage transactionでcommitします。

- event identity 1件
- event ID mapping 1件。scopeはsource application instance + namespace + service ID、valueはtransaction ID + canonical submission digest + exact idempotency key length / bytes
- origin transaction 1件
- storage namespace sequence counterのchecked incrementとimmutable transaction_sequence 1件
- Controller target 1件
- self-contained ServiceIdentity valueとimmutable ServiceDescriptor snapshot binding 1件
- idempotency mapping 1件
- payloadまたはpayload digestと再送可能なbyte列
- EventFact spool entry 1件
- current retry cycle 8 attemptsのdetail budget
- recent cycle summary 4件と固定長cumulative summaryのrecord budget
- NINLIL_M1A_MAX_EVENT_RESUME_OPERATIONS (=8) 件のfixed resume operation / audit / result ledger slotと1件のdiscard operation / audit / result slot。EVENT_SPOOL_BYTESへchecked `8 * 256 + 512 = 2560` logical bytesをpre-reserve
- Receipt、late evidence、terminal Outcomeのrecord budget
- raw evidence detail最大8件とevidence summary record 1件
- TEST origin grant provider ID / revision
- grant ID、evaluated-at、expiry、authorized identities
- event count / byte / inflight / retry-cycle limits snapshot

Controller側のevent journal capacityはEndpointのlocal reservationに含みません。

Portable `EVENT_SPOOL_BYTES` admission costはexactly `payload.length + 2560`です。Admission staging中はその全量を`reserved`に加え、FULL commit後にpayload bytesだけを`used`へ移します。`r = successful_resume_operation_count`、`d = discard_operation_committed ? 1 : 0`とするとlive Eventは`used = payload.length + r * 256 + d * 512`、`reserved = (8 - r) * 256 + (1 - d) * 512`で、常にchecked `used + reserved = payload.length + 2560`です。Attempt detail、recent/cumulative retry summary、storage key/index/padding/CRC等のphysical overheadをportable accountingへ加えません。

Origin grantのexpiryは新しいEventFact admissionを評価する時刻境界です。expiry前にADMITTEDとなったEventFactのownership、payload、spool、current/future retry cycle、Receipt受付、resume、discardを遡及して失効させません。M1aにretroactive revocationはありません。

### Endpoint inbound delivery

EndpointがDeliveryをINBOX_COMMITTEDへ進める前に、次のlocal capacityを確保します。

- inbox / dedup record
- resultまたはDisposition record
- active deferred delivery token slot
- bounded expired-token record slot
- reconcile state / timer record
- DesiredStateはcancel tombstone + cached CANCEL_RESULT record 1件

deferred token capacityがない場合、application callbackを呼んでから失敗してはなりません。Deliveryを受け付けずAPPLICATION_BUSYまたはCAPACITY_EXHAUSTED Dispositionを返します。

### Service identityの寿命

`ninlil_service_identity_t`はself-contained valueです。namespace / service / schemaの`ninlil_text_id_t`はinline bytes、descriptor revision / digestとschema / familyはscalar valueとして、admissionまたはBearer ingress時にdurable recordへcopyします。Reducer snapshot、ordered input、Delivery、Receipt、query snapshotはそれぞれ必要なvalue copyを所有し、API call、Bearer callback、登録元bufferのborrowed pointer / view lifetimeに依存しません。

Service bindingの比較はinline textのlength + exact bytes、descriptor revision / digest、schema version、familyで行います。Pointer address、temporary NUL terminator、process-local descriptor object identityをbindingに使ってはなりません。

### Reservationの解放

- non-terminal transactionのreservationは解放してはなりません。
- terminal transactionはretention終了までquery用recordを保持します。
- EventFact payload/spoolは、required Receiptのdurable commit、または本章の監査付きexplicit discard commitまで解放してはなりません。
- EventFactのcaller-key mappingとevent ID mappingはspool解放と同時に消さず、terminal tombstoneとともに少なくともservice `required_dedup_window_ms`保持します。bounded retention終了後のreclaimは両mappingとtombstoneをatomicに扱い、異なるkeyのaliasを残しません。
- 使用済みEvent resume / discard operationのaudit / request digest / result recordはterminal後のservice dedup retention終了までsilent eviction / reuseしません。各successful resume / discardは対応slotだけを`reserved`から`used`へ移し、live total/high-waterを増やしません。Required Receipt / discard terminal commitはpayload `used`と未使用slot `reserved`を解放し、terminal retention中のportable `used`はexactly `successful_resume_operation_count * 256 + (discard_operation_committed ? 512 : 0)`、`reserved = 0`です。Terminal Eventへ新operationを受理するreusable slotにはしません。
- retry cycle exhaustion、cancel request、Runtime restartはEventFact spool解放理由ではありません。
- 新しいretry cycleを開始する前に、完了cycleのattempt detailをrecent summaryへatomicに圧縮します。recent 4件を超えた古いsummaryは、fixed cumulative cycle count、attempt count、last reason/time、delivery_possible_anyへ畳み込みます。
- retry_cycle_id、cumulative cycle count、cumulative attempt countはchecked uint64です。increment不能ならpublic reason=NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、event_park_cause=COUNTER_EXHAUSTEDでPARKED_RETRYに留まり、required Receiptまたはdiscardだけを許します。NINLIL_REASON_COUNTER_EXHAUSTEDは原因diagnosticでありpublic park reasonを上書きしません。
- summary化と次cycle用record確保をatomicにできない場合、EventFactはPARKED_RETRYに留まります。

## Reducer model

### 形式

M1a state machineは、概念上次のpure reducerとして扱います。

    reduce(previous_snapshot, ordered_input, profile_snapshot)
      -> next_snapshot
      + durable_writes
      + post_commit_effects
      + public_events

同じprevious_snapshot、ordered_input、profile_snapshotからは、同じnext_snapshotとreasonを得なければなりません。entropy、wall clock、I/O結果はreducer外で明示inputに変換します。

### Commit-before-effect

次の順序を必須とします。

1. reducerがnext stateとdurable writesを作る。
2. storage transactionをcommitする。
3. commit成功を確認する。
4. post-commit effectを実行する。
5. public eventまたはReceiptを発行する。

commit前に次を行ってはなりません。

- ADMITTEDをcallerへ返す。
- bearer sendを開始する。
- Endpoint application callbackを呼ぶ。
- Receiptを送る。
- EventFact spoolを解放する。
- terminal OutcomeをUIへ通知する。

### Reducer input identity

各inputは最低限、次を持ちます。

- input_kind
- reducer-local logical time sample。clock epoch / now / trustを含む。Receipt issuerの`evidence_time`とは別物
- durable ingress sequence
- transaction ID
- target identity
- attempt ID。attemptに属する場合
- issuer identity。Receipt / Dispositionの場合
- self-contained service identity value。namespace / service / schemaのinline text ID、descriptor revision / digestを含み、borrowed pointerの寿命に依存しない
- content digestまたはgeneration
- input-specific data

同じinput identityを再度受けた場合、reducerはidempotent no-opにし、重複Observationだけをbounded counterへ加算できます。

## 不変条件

- M1A-INV-001: required Receipt未到達でSATISFIEDにならない。
- M1A-INV-002: targetとtransactionのterminal Outcomeは書き換わらない。
- M1A-INV-003: late evidenceはlatest_evidence_stageを進められるがterminal Outcomeを反転しない。
- M1A-INV-004: admitted transactionにはtarget 1件、descriptor snapshot、local reservation、idempotency mappingがある。
- M1A-INV-005: transaction IDはretry、restart、duplicate、path observationを跨いで不変。
- M1A-INV-006: attempt IDはattempt preparationごとに新規である。
- M1A-INV-007: prepared attemptはsend未確認でもattempt budgetを1消費する。
- M1A-INV-008: DesiredStateCommandをeffect_deadline_at以後に新規dispatchしない。
- M1A-INV-009: EventFactはNINLIL_NO_DEADLINEだけを受け付ける。
- M1A-INV-010: EventFactをrequired Receiptまたは監査付きexplicit discard commitなしに削除しない。
- M1A-INV-011: Receiptはpositive evidenceだけを表す。
- M1A-INV-012: stale attemptのDispositionで現在attemptを失敗させない。
- M1A-INV-013: storage commit不明時にsuccessを返さない。
- M1A-INV-014: OUTCOME_UNKNOWNをSATISFIEDまたはno-effect provenとして扱わない。
- M1A-INV-015: rejected Submissionのpayload ownershipはcallerに残る。
- M1A-INV-016: local admissionに失敗したEventFactの事実保存をNinlilが保証したと表示しない。
- M1A-INV-017: EventFactの1 retry cycleは8 attemptsを超えない。
- M1A-INV-018: 同じBearer availability epochまたはresume operation IDでretry cycleを複数回resetしない。Runtime capacity entryのcapacity_epochと比較しない。
- M1A-INV-019: PARKED_RETRYをterminal Outcomeまたはpayload解放済みとして扱わない。
- M1A-INV-020: discard audit commit前にEventFact payloadを解放しない。
- M1A-INV-021: raw evidence detailはtargetごとに8件を超えない。
- M1A-INV-022: raw detail fullでもvalid higher-stage / new material evidenceをreserved summaryへ集約し、terminal Outcomeを反転しない。
- M1A-INV-023: EventFact event ID mappingはsource application instance + namespace + service ID scopeで一意であり、same event ID / same canonical digest / same idempotency keyの3条件が揃う場合だけ1 transactionへ収束させる。keyだけが異なる場合もconflictとし、alias mappingを追加または既存mappingを上書きしない。
- M1A-INV-024: M1a delivery tokenはcontext ID = transaction ID、generation = 同transactionのreceiver callback invocation countであり、1から始まるchecked uint64とする。tokenのclock_epoch_id / expires_at_msもcallback前のdurable markerとexactly一致し、別Runtime / transaction / delivery / digest / expiryへ移植しない。
- M1A-INV-025: admitted transactionはstorage namespace内で1からmonotonicにchecked割当てたnon-zero `transaction_sequence`を1つ持ち、state mutation、retry、restart、duplicate submissionで変更しない。sequence counter incrementとtransaction / mapping / reservationは同じadmission FULL transactionへcommitする。
- M1A-INV-026: next transaction_sequenceをchecked incrementできない場合は新規admissionをNINLIL_REASON_COUNTER_EXHAUSTEDでREJECTEDとし、sequence counter、既存transaction、mapping、reservationを変更しない。
- M1A-INV-027: public transaction query/listはlocal-origin admission domainだけを列挙する。Inbound Delivery/result-cacheはtransaction_sequence/assuranceを持たず、同じtransaction IDでもreceiver RuntimeのqueryはNOT_FOUND、list件数/sequence counterへ影響0。
- M1A-INV-028: new logical rootだけがnon-zero scheduler owner sequenceを1回割当て、retry/state/revision/restartで変更しない。Counter/owner/root recordは同じFULL commitでall-or-none。
- M1A-INV-029: Receipt/Disposition/Custody/CancelResult/duplicate forward inputはlookup済みexisting ownerへattachし、同ownerのearlier timeとexact same-time priorityをtemporary owner分離で追い越さない。
- M1A-INV-030: Same owner/current epochではearlier logical timeが先、exact same timeだけsemantic priorityを使う。異なるepoch ID bytesを大小比較しない。
- M1A-INV-031: Scheduler cursorは12章11.0表のexactly 1 FULL commitだけへ含め、同じownerを1 stepで2回訪問しない。Cursor commit unknownはそのgroupのstateとall-or-none。
- M1A-INV-032: ordinary Application send後/observation前crashは同じattempt ID/immutable messageだけをduplicate-safe再invokeでき、new attempt/entropy/budgetを作らない。Observation commit済みまたはunknown未解決では再invokeしない。

## 時刻と境界

本節のeffect deadlineとevidence graceはDesiredStateCommandだけに適用します。M1a EventFactにはdeadline timerもevidence close timerも生成しません。

### DesiredStateCommandの基準時刻

Runtimeは新規admissionのresource reservationとstorage transaction開始の前にtrusted clockを1回sampleし、これを**admission reference sample**とします。`admitted_at_ms`はこのpre-commit `ninlil_time_sample_t.now_ms`、`admission_clock_epoch_id`とCommandの`deadline_clock_epoch_id`はそのnon-zero `clock_epoch_id`です。sample、absolute timer、Submission / descriptor / source / target bindingはadmissionの同じFULL transactionにpersistします。commit acknowledgement後に観測した時刻を`admitted_at_ms`として上書きしてはなりません。effect_deadline_atとevidence_close_atは次です。

    effect_deadline_at = admitted_at_ms + effect_deadline_ms
    evidence_close_at = effect_deadline_at + evidence_grace_ms

加算overflow、負値、ServiceDescriptor範囲外はadmission時にREJECTED、reasonはNINLIL_REASON_DEADLINE_INVALIDです。Clock sampleがuncertain、epochがall-zero、または時刻後退を検出した場合はCommandをNINLIL_REASON_CLOCK_UNCERTAINでadmitしません。

Pre-commit sampleの取得だけでNinlil ownershipは成立しません。FULL admission commit OKの時点でだけownership、assurance、transaction_sequence、ADMITTED resultが成立します。Commit中にcurrent timeがeffect_deadline_atへ到達してもadmission commitをREJECTEDへ巻き戻さず、ADMITTED resultは既に所有したtransactionを返します。ただしpost-commit dispatchは禁止し、次のtrusted sampleでdeadline guardをreduceしてEXPIRED / NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCHをdurably commitした後にだけ他workへ進みます。このterminalization commitが失敗または不明ならsend 0のままrecoveryします。

### 境界規則

- effectがeffect_deadline_atと同時刻なら期限内です。
- Receipt inputがeffect_deadline_atと同時刻ならdeadline timerより先に評価します。
- DesiredStateCommandの新規dispatchはtrusted current sampleのepochが`deadline_clock_epoch_id`とexactly一致し、`now_ms < effect_deadline_at`の場合だけ許可します。epoch不一致またはNINLIL_CLOCK_UNCERTAINなsampleの数値をdeadlineと比較してはなりません。
- evidence graceは新しいdispatchを許す延長時間ではありません。
- evidence_grace_msが0の場合も、同時刻のpositive evidence、effect deadline、evidence closeの順で処理します。

### EventFactのNINLIL_NO_DEADLINE

- pre-commit admission referenceのadmitted_at_ms / admission_clock_epoch_idは保持しますが、effect_deadline_atとevidence_close_atを計算しません。
- deadline_clock_epoch_idはall-zero、Bearer / Delivery / Snapshotのduration deadlineはNINLIL_NO_DEADLINEとし、deadline判定にclock sampleを使いません。
- EFFECT_DEADLINEとEVIDENCE_CLOSEをEventFact transactionへ入力してはなりません。
- EventFactのReceipt待ちはattemptごとのbounded attempt_receipt_timeout_msとretry cycleで制御します。
- ATTEMPT_RECEIPT_TIMEOUTはBearer sendのaccepted/custody/LOST_UNKNOWNまたはCORRUPT/invalid possible-delivery observation時刻 + attempt_receipt_timeout_msのchecked additionから生成し、attempt IDへbindingします。Definitive no-sendでは生成しません。
- Receipt未到達の時間が長いことだけを理由にEXPIREDまたはOUTCOME_UNKNOWNへ進めません。
- 運用者にはPARKED_RETRY、public park reason、internal event_park_cause、last attempt、last seen / consumed availability epoch、payload保持中を明示します。

### 期限内effectの証明

Receipt issuerはapplication resultまたはingress evidenceをdurably commitしたlogical timeを`ninlil_time_sample_t evidence_time`として送ります。ControllerもReceipt自体をdurable ingressする時にlocal `ninlil_time_sample_t controller_ingress_time`を固定します。比較可能性は以下のexact fieldだけで判定します。

- issuer `evidence_time.trust == NINLIL_CLOCK_TRUSTED`かつ`evidence_time.clock_epoch_id == deadline_clock_epoch_id`の場合だけ、`evidence_time.now_ms`をdeadline proofに直接使用できます。`now_ms <= effect_deadline_at`ならPROVEN_IN_TIME、それを超えるrequired evidenceはPROVEN_LATEです。
- issuer timeがepoch不一致またはNINLIL_CLOCK_UNCERTAINなら、その数値をdeadlineと比較しません。`controller_ingress_time.trust == NINLIL_CLOCK_TRUSTED`かつ同じdeadline epochで、`controller_ingress_time.now_ms <= effect_deadline_at`の場合だけ、effectはそれ以後ではないと保守的にPROVEN_IN_TIMEにできます。
- fallback ingress timeがdeadline後であることは、effectがdeadline後だった証明になりません。issuer timeも比較不能ならTIME_UNKNOWN / NINLIL_DEADLINE_INDETERMINATEです。
- 証明できないReceiptもlatest evidenceとして保持しますが、deadline_verdictをMETにしません。EventFactではevidence_timeをaudit用に保持するだけでdeadline evidenceを生成しません。

### Effect deadline

DesiredStateCommand targetがrequired evidence未到達でeffect deadlineへ達した場合:

| 事実 | 次状態 |
| --- | --- |
| attempt未作成、deliveryなし、effect不可能を証明 | EXPIRED |
| definitive Dispositionでeffectなしを証明済み | FAILED_DEFINITIVE |
| attempt prepared、send成否不明、delivery、application startのいずれかあり | AWAITING_GRACE |

### Evidence close

evidence_close_atまでにrequired evidenceが期限内effectを証明しない場合:

| Deadline evidence | 事実 | terminal Outcome |
| --- | --- | --- |
| NONE | effectが起きていないことを既に証明 | evidence-close固有判断ではない。先行するdeadline/Disposition reducerをcatch-upし、その規則どおりEXPIREDまたはFAILED_DEFINITIVE |
| PROVEN_LATE | required effectがdeadline後だったと証明 | EXPIRED、reasonはNINLIL_REASON_REQUIRED_EVIDENCE_LATE |
| TIME_UNKNOWN | effectは確認したがdeadline内か証明不能 | OUTCOME_UNKNOWN |
| NONE | effect、保存、適用の可能性を排除できない | OUTCOME_UNKNOWN |

Evidence close時点までactiveである通常caseは、PROVEN_LATE、TIME_UNKNOWN、またはeffect可能性を排除できないNONEです。No-effect proofがあるのにactiveなrecordはcrash/未処理inputのcatch-up対象で、evidence-close reducerが二者択一しません。EXPIREDとFAILED_DEFINITIVEの選択は、deadlineだけが理由ならEXPIRED、deadline前に確定した非再試行failureが理由ならFAILED_DEFINITIVEです。

### Deadline verdict

| 条件 | deadline_verdict |
| --- | --- |
| Commandがまだ判定可能期間内 | PENDING |
| required evidenceがPROVEN_IN_TIME | MET |
| no-effect、PROVEN_LATE、deadline前のdefinitive failure | MISSED |
| effect timingまたはeffect有無を証明不能 | INDETERMINATE |
| EventFact | NOT_APPLICABLE |

M1a public deadline verdictはNOT_APPLICABLEを表現できなければなりません。EventFactをPENDINGのまま無期限表示して代用してはなりません。

## 同一時刻の優先順位

「同じlogical_time」は、同じscheduler owner内でreducer-local clock epoch IDとnow_msがともにexactly一致することです。Current epochでtimeが異なるcandidateはnow_ms昇順が先で、**exact同時刻だけ**次のpriority、durable ingress sequence、target identity byte orderを使います。数字が小さいほど先です。Receipt issuerの`evidence_time`はdeadline proofには使っても、Controller reducer queueの並び替えに使ってはなりません。epochが異なるinputのnow_msを数値比較せず、RECOVERY_FENCEとdurable ingress sequenceで収束させます。Owner間は12章11.0のround-robinであり、全namespaceを時刻sortしません。

| Priority | Input |
| ---: | --- |
| 0 | RECOVERY_FENCE、STORAGE_COMMIT_FAILED、STORAGE_COMMIT_UNKNOWN |
| 1 | DELIVERY_COMPLETE_REQUEST、APPLICATION_RESULT_COMMITTED、RECONCILE_RESULT、DELIVERY_INGRESS_COMMITTED、VALID_RECEIPT |
| 2 | REMOTE_CANCEL_RESULT、DELIVERY_DISPOSITION |
| 3 | EVENT_DISCARD_REQUEST、LOCAL_CANCEL_REQUEST、REMOTE_CANCEL_REQUEST |
| 4 | DEFER_CONTEXT_TIMEOUT |
| 5 | EFFECT_DEADLINE |
| 6 | EVIDENCE_CLOSE |
| 7 | ATTEMPT_RECEIPT_TIMEOUT、RETRY_BUDGET_EXHAUSTED |
| 8 | EVENT_RESUME_REQUEST、AVAILABILITY_EPOCH_AVAILABLE、RECONCILE_DUE |
| 9 | RETRY_DUE、DISPATCH_DUE |
| 10 | Transport Observation、CUSTODY_ACCEPTED |

この順序から次が導かれます。

- 同時刻のvalid ReceiptとcancelではReceiptを先に適用する。
- 同時刻のvalid Receiptと任意のvalid DispositionではReceiptを先に適用する。
- 同時刻のcancelとdeadlineではcancelを先に評価する。
- 同時刻のdeadlineとretryではdeadlineを先に評価し、DesiredStateCommandをdispatchしない。
- 同時刻のvalid required ReceiptとEventFact discardではReceiptを先にcommitし、discardはALREADY_RELEASEDになる。
- 同時刻のEventFact discardとresume / Bearer availability epoch / dispatchではdiscardを先にcommitする。
- 同時刻のdelivery_completeとDEFER token timeoutではdelivery_completeを先にcommitする。
- storage commit failureは、そのcommitに依存するsuccess、Receipt、side effectを発生させない。

このpriorityは、**Runtimeへdurably commit済みのcanonical input**、またはdurable timer/namespace stateから決定的に再構成したinternal candidateにだけ適用します。Public `submit` / `cancel_request` / Event management APIは、呼出中にBearer `receive_next`やprovider callbackを駆動して「同時刻のReceiptがないか」を探してはなりません。API開始前にdurable ingress済みのvalid Receiptは上記priorityで先にreduceしますが、provider内にあるだけのmessageは後のingress sequenceで処理します。APIがcommitしたlocal management inputもcommit後だけordered reducerへ入り、deadline/timer/reconcile dueとnamespace availability observation由来candidateは12章scheduler cutで確定した場合だけ競合へ参加します。

## State definitions

### Submission state

Submissionはadmission前のcaller-owned inputです。M1aは未admitted Submissionをdurable transactionとして保持しません。

| State | Durable | 意味 |
| --- | --- | --- |
| PRESENTED | no | reducerへ渡されたが所有権未移転 |
| TRANSACTION_ID_ALLOCATING | no | 全non-entropy guard/preflight成功後、最大4件の明示draw resultを評価中。所有権/recordなし |
| ADMISSION_COMMITTING | internal | atomic commitを試行中。外部success禁止 |
| ADMITTED | transactionへ変換 | Submission自体は消滅し、transaction IDを返す |
| ALREADY_ADMITTED | existing transaction | 同一key/digestの既存transactionを返す |
| REJECTED | no | Ninlilは所有しない |
| IDEMPOTENCY_CONFLICT | no | 同じkeyでdigestが異なる |
| COMMIT_UNKNOWN | backend dependent | 所有権を断定せず同じkeyでreconcileが必要 |

### Target state

M1aはtarget 1件ですが、後続group対応のためtarget stateをtransaction stateと分けます。

### Active

- READY: dispatch可能。
- ATTEMPT_PREPARED: attempt ID、budget消費、immutable messageをcommit済みで、ordinary Application send observationはまだない。Send前またはobservation前crashのいずれでも、同じattemptだけをduplicate-safeに再開するdurable gate。
- AWAITING_EVIDENCE: deliveryまたはReceipt待ち。
- RETRY_WAIT: target / EventFact spoolのinternal bounded retry timer待ち。public Transaction stateへはM1a-active WAITING_WINDOWとして射影し、public RETRY_WAITという別stateを作らない。
- AWAITING_GRACE: effect deadline後、evidence close待ち。
- PARKED_RETRY: EventFactがpayloadを保持したまま、新しいretry cycle開始条件を待つ。

### Terminal

- SATISFIED
- EXPIRED
- CANCELLED_BEFORE_EFFECT
- FAILED_DEFINITIVE
- OUTCOME_UNKNOWN

### Orthogonal fields

各targetはstate以外に次を保持します。

- highest_receipt_stage
- latest_evidence_stage
- deadline_verdict
- effect_certainty: NONE、NO_EFFECT_PROVEN、EFFECT_POSSIBLE。12章のknown enum以外を作らない
- dispatch_fenced
- cancel_state: NONE、PENDING_REMOTE_FENCE、FENCED_BEFORE_DISPATCH、TOO_LATE_EFFECT_POSSIBLE
- dedicated cancel_attempt_id、cancel_prepare_committed、cancel_send_gate: NEVER_INVOKED / WOULD_BLOCK_RETRYABLE / INVOKED_CLOSED、cancel_send_invocation_count、cached cancel result。DesiredStateだけ
- attempts_used
- current_attempt_id
- internal retry timer: local clock epoch + retry_not_before_ms。public / wireからabsolute値を受けない
- terminal_reason
- deadline_evidence: NONE、PROVEN_IN_TIME、PROVEN_LATE、TIME_UNKNOWN

### Transaction state

M1aのtarget_countは常に1なので、transaction Outcomeはtarget Outcomeと同じです。Active stateはtarget stateを次へ射影します。WAITING_WINDOWはM1aでreachableなactive public stateであり、future reserved valueとして扱ってはなりません。

Transaction recordはstate / Outcomeと直交するimmutable `transaction_sequence`を持ちます。これはmutation sequenceやjournal sequenceではなく、1 logical transactionに1度だけadmission FULL commitで付与します。`ALREADY_ADMITTED`、retry、Receipt、cancel、resume / discard、terminal transitionでnew sequenceを割り当ててはなりません。Query/list cursorの挙動はstate reducerではなく12章ABI contractの正本に従います。

| Target | Transaction |
| --- | --- |
| READY | READY |
| RETRY_WAIT | WAITING_WINDOW |
| PARKED_RETRY | PARKED_RETRY |
| ATTEMPT_PREPARED | DISPATCHING |
| AWAITING_EVIDENCE、AWAITING_GRACE | AWAITING_EVIDENCE |

terminal Outcomeは同名へ射影します。

### Endpoint Delivery state

DesiredStateCommandを受けるEndpointは、transaction + target + digest + generationをkeyに状態を保持します。

| State | 意味 |
| --- | --- |
| ABSENT | inbox/result cacheにrecordなし |
| INBOX_COMMITTED | envelope、schema、payload validationとinbox commit完了 |
| DELIVERY_STARTED | callback前にdelivery tokenのcontext ID / generation、completion clock epoch / expiryを含むdurable marker完了 |
| DEFERRED_WAIT | callbackがDEFERを返したactive projection。DELIVERY_STARTEDのdurable tokenをそのまま保持 |
| RESULT_COMMITTED | application resultとhighest evidenceをcommit済み |
| DISPOSITION_COMMITTED | negative dispositionをcommit済み |
| RECOVERY_REQUIRED | effect後result不明等でapply contractによるreconcileが必要 |
| RECONCILE_WAIT | on_reconcileがRETRY_LATERを返し、bounded not-before待ち |

RESULT_COMMITTEDとDISPOSITION_COMMITTEDのrecordはdescriptorのdedup window終了まで保持します。

DesiredState Endpoint Deliveryはstateと直交するcancel tombstoneを持ちます。Tombstoneはmatching dedicated cancel attempt ID、original transaction / source / target / service / digest / generation binding、dispatch_fenced、cached CANCEL_RESULTを保持し、terminal result-cache retentionまで削除しません。

DELIVERY_STARTED recordは最低限、delivery tokenのcontext ID / generation / clock_epoch_id / expires_at_ms、delivery identity、delivery_started_at clock epoch / ms、completion_expires_at_ms、token active、prior callback invocationsを持ちます。M1aのcontext IDはtransaction IDと完全一致し、generationはそのreceiverで同transactionに対してcallbackを呼ぶ回数の1始まりchecked uint64です。tokenのclock_epoch_idはdelivery_started_atのepoch、expires_at_msはcompletion_expires_at_msと一致します。tokenは発行Runtimeとtransaction / delivery / digest / expiryにbindingし、同じtokenを別Runtimeまたは別Deliveryへ再利用してはなりません。

### EventFact spool state

EventFactのOutcomeとorigin spool lifecycleは別の軸です。

| State | 意味 |
| --- | --- |
| HELD_READY | durable local admission済み、送信可能 |
| ATTEMPT_PREPARED | attemptをdurable commit済み |
| AWAITING_RECEIPT | send後、required Receipt待ち |
| RETRY_WAIT | retry_not_before待ち |
| PARKED_RETRY | 8-attempt cycle完了またはoperator action待ち。payload保持、timer送信なし |
| DISCARD_COMMITTING | in-memory transient。discard auditとtombstoneをatomic commit中。外部完了表示禁止 |
| DISCARDED | audit commit後にpayload解放済み。required Receipt未達のterminal tombstone |
| RELEASED | required Receipt commit後にpayload解放済み。dedup tombstoneはretention中 |

EventFact spoolは追加で次を保持します。

- retry_cycle_id
- attempts_in_cycle。0〜8
- cumulative_attempts
- last_seen_availability_epoch
- last_consumed_availability_epoch
- last_resume_operation_id
- public_park_reason。PARKED_RETRYでは常にNINLIL_REASON_EVENT_RETRY_CYCLE_PARKED
- event_park_cause: NINLIL_EVENT_PARK_CAUSE_NONE、NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT、NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE、NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLE、NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION、NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTED
- spool_revision
- delivery_possible
- discard audit reference。DISCARDEDの場合

event_spool_revisionはadmission commitで1です。Spool lifecycle、attempt/retry、new evidence material/Receipt/custody、resume/discardを意味的に変える各FULL commitでchecked incrementします。Exact duplicate Receiptはdiagnostic duplicate counterとsaturating record revisionだけを更新し、spool revisionを変えません。Non-terminal incrementがUINT64_MAX-1へ達するcommitでPARKED_RETRY / COUNTER_EXHAUSTEDへ同時に進め、その後はrequired Receiptまたはdiscard terminal commitだけがchecked +1してMAXへ進められます。

Required Receiptまたはdiscardのterminal commitはcurrent revisionをchecked +1し、得たterminal revision `R`（通常は2以上、headroom端ではMAX）をabsorbingにします。常にMAXへjumpしません。Valid late evidenceはraw/summary、late flag/count、latest evidence、saturating `record_revision`、late-evidence metricだけを更新し、spool revision `R`を維持します。Exact duplicateもRを維持します。Late evidenceはterminal Outcome/reason/tombstone/payload releaseやmanagement expected revisionを変更しません。Terminal commit unknownの解決前はreduceせず、authoritative terminal record確定後に適用します。

## Input catalog

| Input | 必須binding |
| --- | --- |
| SUBMIT | self-contained service identity value + descriptor revision/digest、idempotency key、canonical digest、target、payload digest |
| TRANSACTION_ID_DRAW_RESULT | pending Submission identity、draw ordinal 1..4、Port status、exact 16-byte candidate、all-zero flag、active/retained transaction index collision lookup result |
| ORIGIN_GRANT_EVALUATED | provider/revision、decision、grant ID、evaluated-at/expiry、source/service/target、limits |
| LOCAL_CANCEL_REQUEST | DesiredState transaction ID、owner execution context、trusted local reducer time |
| REMOTE_CANCEL_REQUEST | DesiredState transaction、original source / target / service / digest / generation binding、non-zero dedicated cancel attempt ID、durable ingress sequence |
| CANCEL_SEND_RESULT | dedicated cancel attempt ID、Bearer status / accepted observation |
| REMOTE_CANCEL_RESULT | DesiredState transaction、reverse source/targetとoriginal service / digest / generation binding、matching dedicated cancel attempt ID、FENCED_BEFORE_DISPATCHまたはTOO_LATE_EFFECT_POSSIBLE、durable ingress sequence |
| DISPATCH_DUE | transaction、target、logical time |
| ATTEMPT_ID_DRAW_RESULT | transaction、target、purpose=APPLICATION/CANCEL、draw ordinal 1..4、port status、exact 16-byte candidate、zero/collision lookup result |
| ATTEMPT_PREPARE_COMMITTED | transaction、target、new attempt ID |
| TX_GATE_RESULT | transaction、attempt、message kind、normalized OK-valid / TEMPORARY-zero / DENIED-zero / CONTRACT_FENCE、trusted acquire time、permit presence/binding |
| BEARER_RESULT | transaction、attempt、message kind、12章closed send status/output shape、accepted/no-send/possible-delivery/port-contract-fence、availability epoch |
| DELIVERY_INGRESS_COMMITTED | transaction、target、self-contained service identity value、digest、generation、deadline clock epoch / absolute deadline |
| DELIVERY_COMPLETE_REQUEST | copy済みdelivery token全value。context ID = transaction ID、generation = exact active callback invocation count、clock_epoch_id / expires_at_ms = durable marker、発行Runtime / delivery / digest binding、trusted current time sample、application result |
| DEFER_CONTEXT_TIMEOUT | delivery tokenのcontext ID / generation、completion clock epoch / completion_expires_at_ms |
| RECONCILE_DUE | delivery identity、reconcile generation、internal local not-before |
| RECONCILE_RESULT | delivery identity、action、`KNOWN_RESULT`の場合だけknown result。`RETRY_LATER`を含む他actionではout resultをignore |
| APPLICATION_RESULT_COMMITTED | transaction、target、stage、exact evidence bytes、internal evidence digest |
| VALID_RECEIPT | transaction、target、issuer、self-contained service identity value、stage、content digest/generation、`ninlil_time_sample_t evidence_time`、Controller durable ingress time、exact evidence bytes |
| CUSTODY_ACCEPTED | transaction、target、self-contained service identity、content digest/generation、triggering non-zero Application attempt ID、receiver durable ingress sequence |
| DELIVERY_DISPOSITION | transaction、target、attempt ID、kind、relative retry_delay_ms、retry guidance、effect certainty |
| RETRY_DUE | transaction、target、attempt ID、logical time |
| EFFECT_DEADLINE | transaction、target、deadline_clock_epoch_id、effect_deadline_at |
| EVIDENCE_CLOSE | transaction、target、deadline_clock_epoch_id、evidence_close_at |
| ATTEMPT_RECEIPT_TIMEOUT | DesiredStateまたはEventFact transaction、attempt ID、send_accepted_at clock epoch / msからchecked導出したtimeout |
| AVAILABILITY_EPOCH_AVAILABLE | ordered ingressではないinternal candidate。Persist済みnamespace Bearer stateのidentity、strictly monotonic availability_epoch、available=1、Eventのseen/consumed/park-cause guardからwork kind `AVAILABILITY_CONSUME`として再構成 |
| EVENT_RESUME_REQUEST | EventFact transaction、operation/actor ID、canonical request digest、expected spool revision、resume reason、audit metadata |
| EVENT_DISCARD_REQUEST | EventFact transaction、operation/actor/event ID、canonical request digest、expected content digest/revision、ack、discard reason、audit metadata |
| STORAGE_COMMIT_FAILED | operation ID、definite failure |
| STORAGE_COMMIT_UNKNOWN | operation ID、commit acknowledgement不明 |
| RECOVERY_FENCE | runtime epoch、recovered storage revision |

## Durable scheduler ownership

12章11.0の`last_assigned_scheduler_owner_sequence`、`last_visited_scheduler_owner_sequence`、`last_assigned_ordered_input_sequence`が唯一のscheduler counter/cursor正本です。Stage 5はnew namespaceでこの3値と`transaction_sequence`の計4値を0としてprofile/capacity metadataと同じ初期FULL commitへ含め、reopenではexact loadし、欠損/部分存在/wrapをstorage corruptionとしてBearer open前に停止します。

- New origin transaction、初見inbound APPLICATION Delivery、APPLICATIONより先の初見cancel tombstoneだけがnew owner sequenceを割り当てます。Admission/ingress/tombstone record、owner sequence counter、owner bindingは同じFULL commitです。
- Receipt/Disposition/Custody/CancelResult、duplicate APPLICATION/CANCEL_REQUEST、public management inputはdurable copy/lookup時に既存owner sequenceへattachします。これらをtemporary ownerへ分けず、同じownerのdeadline/timer/inputと13章time/priorityで比較します。
- Every durable ingress/management inputは既存ownerでもnew ownerでもordered-input sequenceを同じFULL commitで割り当てます。Counter MAXではnew ordered inputを作らず、owner MAXでもexisting-owner inputは継続します。
- Terminal/retention cleanupはowner recordとcursorを別々に削除せず、ownerのlast retained group cleanupでownerを削除します。Cursor値自体は削除済みsequenceを保持でき、12章upper-bound再開を使います。Owner/input/cursorを含むCOMMIT_UNKNOWNは該当FULL groupだけall-or-noneです。
- Runtime recovery/Bearer state observationはowner外barrierです。Ringのcandidate order、cursor placement、same-attempt send replay、ingress lane順は12章11.0だけを正本とし、本章priorityはexact same owner/epoch/time内だけに適用します。

## TEST origin grant guard

M1aのORIGIN_WITH_GRANT EventFactは、TEST origin authorization / grant providerのdecisionを必要とします。callerの自己申告だけでgrant済みにしてはなりません。

新規EventFact admissionの順序:

1. Submission syntaxとcanonical digestを検査する。
2. caller idempotency key mappingと、source application instance + namespace + service ID scopeのevent ID mappingを検査する。
3. same key / same digestで既存admissionがあり、EventFactではsame event ID / same canonical digest / same idempotency keyの3条件も揃うなら、現在のgrant expiryに関係なくALREADY_ADMITTEDを返す。
4. same key / different digest、EventFactのsame key / same digest / different event ID、same event ID / different canonical digest、same event ID / same canonical digestだがdifferent idempotency key、または2つのmappingが別transactionを指す場合はIDEMPOTENCY_CONFLICTです。conflictでnew key / event aliasを追加せず、既存mappingも上書きしません。Conflict結果のexisting transaction ID / digestはcaller-key mappingが存在すればそのpair、存在しなければevent ID mappingのpairを返します。両mappingが別transactionでもfieldを混合せずcaller-key mappingを優先し、mapping先recordを検証できない場合はStorage failureとしてfail closedします。
5. 両mappingがない新規の場合だけtrusted admission reference sampleを取得する。
6. `transaction_sequence`、次に`scheduler_owner_sequence`のchecked headroomを検査する。どちらかMAXならprovider/entropy/reservation 0でCOUNTER_EXHAUSTED rejection。
7. Counter headroomがある場合だけproviderをexactly 1回評価する。
8. decision=ALLOW、request.nowがtrusted、decision clock epochがrequest.now epochとexact match、valid_from <= evaluated_at=request.now < expiry、source / application / service revision / targetが一致、limits内であることをguardする。
9. 12章7.1のquota/grant/resource guardを順に検査し、transaction IDを最大4 drawする。
10. transaction/scheduler sequence increment、transaction ID index、quota/reservation、grant snapshot、caller idempotency mapping、event ID mapping、EventFact/owner admission recordを同じFULL transactionでcommitする。

Grant snapshotは最低限、次を含みます。

- provider_id / provider_revision
- decision_digest
- grant_id / grant_revision
- clock_epoch_id + evaluated_at_ms / valid_from_ms / expires_at_ms。すべてrequest trusted nowと同epoch
- requestのsource device / site / membership、service / descriptor、target binding
- retry_delay_ms。0はprovider指定delayなし
- max_payload_bytes
- max_active_spool_count / max_active_spool_bytes
- rate_window_ms / max_admissions_per_window
- max_attempts_per_retry_cycle

Guard結果:

| 条件 | Submission result |
| --- | --- |
| ORIGIN_AUTH_OK、allowed=1、clock epoch=request trusted now epoch、valid_from <= evaluated_at=request.now < expires、binding一致、limits内、retry_delay_ms=0 | admission継続 |
| ORIGIN_AUTH_OK、allowed=0、valid deny reason | NINLIL_OK + REJECTED / 12章registryにあるdecisionのexact public reason |
| ORIGIN_AUTH_OKだがpartial、unknown reason、ALLOW binding/expiry/limit不整合 | API NINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALID / reason NONE / zero assurance。transactionなし、Runtime degraded cause NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLEをadd |
| provider TEMP failure | API NINLIL_E_WOULD_BLOCK + NINLIL_SUBMISSION_INVALID / reason NONE / zero assurance。transactionなし、Submission ownershipはcaller、health cause add 0 |
| provider PERMANENT failure / invalid decision | API NINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALID / reason NONE / zero assurance。transactionなし、Submission ownershipはcaller、Runtime degraded cause NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLEをadd |

Valid DENYは12章のreason / retry-guidance組み合わせをそのまま返します。`RETRY_SAME_AFTER`のみrelative retry_delay_msを0..NINLIL_M1A_MAX_RETRY_DELAY_MSで返せ、他guidanceでは0必須です。この値はSubmission resultの相対delayであり、EventFact spool timerやabsolute timeを作りません。

Provider API errorのout resultはNINLIL_SUBMISSION_INVALID / reason NINLIL_REASON_NONE / guidance NINLIL_RETRY_NEVER / delay 0 / zero assuranceです。NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLEはSubmission reasonではなくRuntime healthのdegraded reasonとしてだけreachableで、12章default guidance metadataはNINLIL_RETRY_OPERATOR_ACTIONです。同じproviderの後続valid evaluationで該当causeをclearします。Temporary failureではadd/clearせず、既存health causeも変更しません。

ADMITTED後にgrant expiryへ達しても、既存EventFactのstateを変更するinputを生成しません。payloadを削除せず、retry cycleを取消さず、Receipt、Bearer availability epoch resume、operator resume、discardを引き続き本章どおり処理します。

## Submission reducer

このreducerへ到達するservice handleは登録時にknown familyとdescriptor rangeを検証済みです。Unsupported familyはservice registrationのNINLIL_E_UNSUPPORTED、attempt Receipt timeout不正はservice registrationのNINLIL_E_INVALID_ARGUMENTで終了します。Caller payloadとcontent digestの不一致は下表どおりAPI NINLIL_E_INVALID_ARGUMENT / reason NONEです。これらをSubmission REJECTEDへ変換しません。

| Current | Input / Guard | Next | Public result | Reason |
| --- | --- | --- | --- | --- |
| PRESENTED | target_count != 1 | REJECTED | REJECTED | NINLIL_REASON_TARGET_COUNT_UNSUPPORTED |
| PRESENTED | schema不正 | REJECTED | REJECTED | NINLIL_REASON_INVALID_SCHEMA |
| PRESENTED | payload length不正 | REJECTED | REJECTED | NINLIL_REASON_INVALID_PAYLOAD_LENGTH |
| PRESENTED | caller payload SHA-256 / content_digest mismatch | PRESENTED | NINLIL_E_INVALID_ARGUMENT | NINLIL_REASON_NONE |
| PRESENTED | deadline不正 | REJECTED | REJECTED | NINLIL_REASON_DEADLINE_INVALID |
| PRESENTED | finite EventFact deadline | REJECTED | REJECTED | NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED |
| PRESENTED | evidence不正 | REJECTED | REJECTED | NINLIL_REASON_EVIDENCE_UNSUPPORTED |
| PRESENTED | DesiredState same key、same digestのmappingあり | ALREADY_ADMITTED | ALREADY_ADMITTED | NINLIL_REASON_NONE |
| PRESENTED | same key、different digest | IDEMPOTENCY_CONFLICT | IDEMPOTENCY_CONFLICT | NINLIL_REASON_IDEMPOTENCY_CONFLICT |
| PRESENTED | EventFact same event ID、same canonical digest、same caller key | ALREADY_ADMITTED | ALREADY_ADMITTED | NINLIL_REASON_NONE |
| PRESENTED | EventFact same caller key、same canonical digest、different event ID | IDEMPOTENCY_CONFLICT | IDEMPOTENCY_CONFLICT | NINLIL_REASON_IDEMPOTENCY_CONFLICT |
| PRESENTED | EventFact same event ID、same canonical digest、different caller key | IDEMPOTENCY_CONFLICT | IDEMPOTENCY_CONFLICT | NINLIL_REASON_IDEMPOTENCY_CONFLICT |
| PRESENTED | EventFact same event ID、different canonical digest | IDEMPOTENCY_CONFLICT | IDEMPOTENCY_CONFLICT | NINLIL_REASON_IDEMPOTENCY_CONFLICT |
| PRESENTED | caller key mappingとevent ID mappingが別transactionを指す | IDEMPOTENCY_CONFLICT | IDEMPOTENCY_CONFLICT | NINLIL_REASON_IDEMPOTENCY_CONFLICT |
| PRESENTED | 新規admissionのnext transaction_sequenceをchecked increment不能 | REJECTED | REJECTED | NINLIL_REASON_COUNTER_EXHAUSTED |
| PRESENTED | 新規admissionのnext scheduler owner sequenceをchecked increment不能 | REJECTED | REJECTED | NINLIL_REASON_COUNTER_EXHAUSTED |
| PRESENTED | new EventFact、grant missing / denied / binding mismatch | REJECTED | REJECTED | NINLIL_REASON_GRANT_INVALID |
| PRESENTED | new EventFact、grant expired | REJECTED | REJECTED | NINLIL_REASON_GRANT_EXPIRED |
| PRESENTED | new EventFact、target authorization mismatch | REJECTED | REJECTED | NINLIL_REASON_TARGET_UNAUTHORIZED |
| PRESENTED | new EventFact、grant provider TEMP failure | PRESENTED | NINLIL_E_WOULD_BLOCK + NINLIL_SUBMISSION_INVALID | NINLIL_REASON_NONE |
| PRESENTED | new EventFact、grant provider PERMANENT failure / invalid decision | PRESENTED | NINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALID | NINLIL_REASON_NONE |
| PRESENTED | service inflight prospective count > descriptor limit | REJECTED | REJECTED | NINLIL_REASON_CAPACITY_EXHAUSTED |
| PRESENTED | fixed-window prospective admission count > descriptor limit | REJECTED | REJECTED | NINLIL_REASON_RATE_EXHAUSTED |
| PRESENTED | fixed-window prospective logical payload bytes > descriptor limit | REJECTED | REJECTED | NINLIL_REASON_RATE_EXHAUSTED |
| PRESENTED | new EventFact、grant payload/active spool prospective limit exceeded | REJECTED | REJECTED | NINLIL_REASON_GRANT_LIMIT_EXCEEDED |
| PRESENTED | new EventFact、grant prospective admission count exceeded | REJECTED | REJECTED | NINLIL_REASON_RATE_EXHAUSTED |
| PRESENTED | local reservation不足 | REJECTED | REJECTED | NINLIL_REASON_CAPACITY_EXHAUSTED |
| PRESENTED | 全non-entropy guard、idempotency、authorization、capacity preflight成功 | TRANSACTION_ID_ALLOCATING | none | NINLIL_REASON_NONE |
| TRANSACTION_ID_ALLOCATING | draw 1..3がPort failure/partial/all-zero/collision | TRANSACTION_ID_ALLOCATING | none | NINLIL_REASON_NONE |
| TRANSACTION_ID_ALLOCATING | draw 1..4がvalid non-zero unique | ADMISSION_COMMITTING | none | NINLIL_REASON_NONE |
| TRANSACTION_ID_ALLOCATING | draw 4もPort failure/partial/all-zero/collision | PRESENTED | NINLIL_E_ENTROPY + SUBMISSION_INVALID | NINLIL_REASON_NONE |
| ADMISSION_COMMITTING | atomic commit成功 | ADMITTED | ADMITTED_READY | NINLIL_REASON_NONE |
| ADMISSION_COMMITTING | begin/stage/commitがdefinite NO_SPACE | REJECTED | NINLIL_OK + REJECTED | NINLIL_REASON_CAPACITY_EXHAUSTED |
| ADMISSION_COMMITTING | begin/stage/commitがdefinite BUSY | PRESENTED | NINLIL_E_WOULD_BLOCK + SUBMISSION_INVALID | NINLIL_REASON_NONE |
| ADMISSION_COMMITTING | begin/stage/commitがdefinite IO_ERROR | PRESENTED | NINLIL_E_STORAGE + SUBMISSION_INVALID | NINLIL_REASON_NONE |
| ADMISSION_COMMITTING | begin/stage/commitがCORRUPTまたは内部schema不整合 | PRESENTED | NINLIL_E_STORAGE_CORRUPT + SUBMISSION_INVALID | NINLIL_REASON_NONE |
| ADMISSION_COMMITTING | commit結果不明 | COMMIT_UNKNOWN | NINLIL_E_STORAGE_COMMIT_UNKNOWN + SUBMISSION_INVALID | NINLIL_REASON_NONE |

COMMIT_UNKNOWNのcallerは新しいidempotency keyを作ってはなりません。同じkey/digestで再提出し、ALREADY_ADMITTEDまたは新しいatomic admissionへ収束させます。

Admission Storage statusの公開射影は14章の規範mappingと12章Submission result全field matrixを同時に満たします。`NO_SPACE`だけがsemantic capacity rejectionです。`BUSY`、definite `IO_ERROR`、`CORRUPT`、`COMMIT_UNKNOWN`はAPI errorであり、outer result header以外のtransaction ID、digest、nested assuranceをzero、public reasonを`NONE`にします。内部health causeとpublic Submission reasonを混同しません。Definite non-commitではtransaction/index/mapping/sequence/quota/reservation/owner/payloadのdurable mutationは0、`COMMIT_UNKNOWN`ではatomic groupのall-or-noneをauthoritative recoveryまで推測しません。

Provider TEMP rowはhealth causeを追加しません。PERMANENT / invalid rowだけがNINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE causeをaddし、Runtime health projectionを12章11.3の固定priorityから再導出します。どちらのAPI errorもSubmission ownership、transaction、spool、assuranceを作りません。

Transaction ID drawはPort call自体をreducer内で行わず、owner-thread orchestratorが各returnを`TRANSACTION_ID_DRAW_RESULT`へ正規化します。Ordinalは1から連続し、valid candidate後の追加drawはinvalid internal inputです。4th failureではtransaction ID/mapping/sequence/resource reservation/storage write/ownershipを0、Submission resultはINVALID/all-field error matrix、health causeは`NINLIL_REASON_OUTCOME_UNKNOWN`をaddしてDEGRADEDを再導出します。Collision lookupのStorage failureはdraw failureに数えずStorage API statusとして終了します。Valid candidateはtransaction sequence、scheduler owner sequence、mapping、quota/reservation、admission/owner recordと同じFULL commitで初めてindexへ追加し、commit failure/unknownでorphan ID/owner indexを残しません。

Quota rowsのkey/unit、guard precedence、guidance/delayは12章7.1が正本です。Reducer previous/profile snapshotはpersist済みinflight/window key/count/bytesを含みます。Admission FULL writeへquota increment、最初のterminal FULL writeへinflight decrementを含め、ALREADY/conflict/rejected/API errorでは変更しません。Admission COMMIT_UNKNOWNはtransaction/mapping/quota all-or-none、terminal COMMIT_UNKNOWNはrecovery確定までinflightを解放済みと推測しません。

## Attempt ID allocation

Applicationとremote-cancelの各logical ATTEMPT_PREPAREは、prepare recordを作る直前にowner threadで`entropy.fill(..., 16)`を呼び、16 bytesをbyte-order変換せずattempt ID candidateにします。

- 1 attempt IDのcandidate drawは合計最大4回です。Port failure、partial fill、all-zero、active / retained attempt ID indexとのcollisionはそれぞれ1 callを消費し、valid non-zero unique candidateを得た時点で停止します。
- Attempt ID indexはstorage namespace内でrestartを跨いでuniqueです。Index追加、attempt budget消費、ATTEMPT_PREPARED recordは同じFULL transactionへcommitします。Commit前にcandidateを「消費済みattempt」と表示しません。
- Retained indexへ入るのはlocal Runtimeが生成したApplication/cancel attempt IDだけで、remoteからechoされたIDは追加しません。Entryはparent transaction/kind/attempt recordへbindingし、parent nonterminal中とterminal transaction retention中は削除しません。Exclusive retention cleanupはparent transaction/target/idempotency/evidence、全Application/cancel attempt record/index、transaction ID index、resource releaseを同じFULL transactionで削除します。Commit OK前はcollision、OK後だけcandidate再利用可です。COMMIT_UNKNOWNではgroup all-or-noneを解決するまで再利用せずnamespaceをfenceします。
- Network duplicateは既存attempt IDを維持し、logical retryだけがnew IDをdrawします。ALREADY / REJECTED / conflict、attemptを作らなretry poll、duplicate cancel APIはentropyを消費しません。
- 4 callsでvalid candidateを得られなければNINLIL_E_ENTROPYです。ATTEMPT_PREPARED record、attempt budget消費、Tx permit、Bearer sendはすべて0、Runtimeへpriority 8のNINLIL_REASON_OUTCOME_UNKNOWN entropy causeをaddし、healthを固定priorityから再導出します。Fallback PRNG、clock、device ID、counterからIDを作りません。
- Collision index lookup自体のstorage failureはNINLIL_E_ENTROPYへ変換せず、STORAGE / STORAGE_COMMIT_UNKNOWNの規則でfail closedします。

## DesiredStateCommand target reducer

| Current | Input / Guard | Next | Effect / Reason |
| --- | --- | --- | --- |
| READY、RETRY_WAIT | DISPATCH_DUE、trusted current sampleがdeadline epochと一致、now < deadline、internal retry timerなしまたは同じlocal epochでnot-before到達、budgetあり、max 4 draw内でunique non-zero attempt ID取得 | ATTEMPT_PREPARED | attempt index + record + budget消費をFULL commit |
| READY、RETRY_WAIT | attempt ID max 4 draw failure | current | NINLIL_E_ENTROPY、NINLIL_REASON_OUTCOME_UNKNOWN entropy health causeをadd、attempt / permit / send 0 |
| READY、RETRY_WAIT | DISPATCH_DUE、now >= deadline | EXPIRED | NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH |
| ATTEMPT_PREPARED | TX_GATE_RESULT=OK-valid | ATTEMPT_PREPARED | state commit 0。同じsend micro-operation内でvalid permitを使いBearer sendし、return observationを次rowでFULL commit |
| ATTEMPT_PREPARED | TX_GATE_RESULT=TEMPORARY、budget/deadline/clock guard成立 | RETRY_WAIT | attempt消費済み、NO_EFFECT_PROVEN、fixed backoff、NINLIL_REASON_TRANSPORT_RETRY |
| ATTEMPT_PREPARED | TX_GATE_RESULT=TEMPORARY、budget exhausted | FAILED_DEFINITIVE | NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT、Bearer send 0 |
| ATTEMPT_PREPARED | TX_GATE_RESULT=DENIED | FAILED_DEFINITIVE | NO_EFFECT_PROVEN、NINLIL_REASON_APPLICATION_FAILED、automatic retry/Bearer send 0 |
| ATTEMPT_PREPARED | TX_GATE_RESULT=CONTRACT_FENCE | FAILED_DEFINITIVE | DENIED row + Runtime DEGRADED / OUTCOME_UNKNOWN internal cause |
| ATTEMPT_PREPARED | BEARER_RESULT=WOULD_BLOCK/UNAVAILABLE、retry guard成立 | RETRY_WAIT | NO_EFFECT_PROVEN、permit release、fixed backoff、NINLIL_REASON_TRANSPORT_RETRY、send observation+cursorをFULL commit |
| ATTEMPT_PREPARED | BEARER_RESULT=DENIED | FAILED_DEFINITIVE | NO_EFFECT_PROVEN、permit release、NINLIL_REASON_APPLICATION_FAILED、send observation+cursorをFULL commit |
| ATTEMPT_PREPARED | BEARER_RESULT=OK accepted/custody or LOST_UNKNOWN | AWAITING_EVIDENCE | effect_certainty=EFFECT_POSSIBLE、send observation+cursorをFULL commit、permit release 0 |
| ATTEMPT_PREPARED | BEARER_RESULT=CORRUPT/EMPTY/unknown/invalid OK output | AWAITING_EVIDENCE | effect_certainty=EFFECT_POSSIBLE、send observation+cursorをFULL commit、permit release 0、Runtime DEGRADED / OUTCOME_UNKNOWN source |
| ATTEMPT_PREPARED、AWAITING_EVIDENCE | DELIVERY_INGRESS_COMMITTED / valid positive reverse input | AWAITING_EVIDENCEまたはSATISFIED | same-attempt send observation未commitでもbinding済みinputを優先し、new attempt/send 0 |
| AWAITING_EVIDENCE | current ATTEMPT_RECEIPT_TIMEOUT、send=ACCEPTED / DURABLE_CUSTODY / LOST_UNKNOWN / corrupt-or-invalid possible delivery、required evidence未到達 | AWAITING_EVIDENCE | EFFECT_POSSIBLEをFULL commit。NO_EFFECTと推測せず、timeout自体でRETRY_WAITへ進まない |
| active | valid CUSTODY_ACCEPTED、known attempt/binding | AWAITING_EVIDENCE | remote durable custodyをFULL commitしcurrent attempt Receipt timeout/retry candidateをclear。Required application evidence/evidence close/payload retentionは維持 |
| any | stale old-attempt ATTEMPT_RECEIPT_TIMEOUT | current不変 | bounded stale observationだけ、current attempt / budget / timer不変 |
| AWAITING_EVIDENCE | RETRY_DUE、EFFECT_POSSIBLE、safe apply-contract guard、budget / deadline / cancel fence guard成立、unique attempt ID取得 | ATTEMPT_PREPARED | old attemptのevidence受付を保ったままnew logical attemptをFULL commit |
| AWAITING_EVIDENCE | RETRY_DUE、safe apply-contract guard不成立 | AWAITING_EVIDENCE | send 0。evidence closeまで待ち、不明ならOUTCOME_UNKNOWN |
| active | VALID_RECEIPT、stage < required | AWAITING_EVIDENCEまたはAWAITING_GRACE | highest stage更新 |
| active | VALID_RECEIPT、required到達、期限内effect証明 | SATISFIED | NINLIL_REASON_REQUIRED_EVIDENCE_MET |
| active | VALID_RECEIPT、required到達、PROVEN_LATE | EXPIRED | latest evidence更新、NINLIL_REASON_REQUIRED_EVIDENCE_LATE |
| active | VALID_RECEIPT、required到達、TIME_UNKNOWN | AWAITING_GRACE | latest evidence更新、deadline時刻は未確定 |
| active | exact matrixのNO_EFFECT_PROVEN + RETRY_SAME_AFTER、budgetあり、relative delayから導出したinternal retry_not_before_ms < deadline、timer epoch = deadline epoch | RETRY_WAIT | matrixのexact reason |
| active | exact matrixのNO_EFFECT_PROVEN + RETRY_MODIFIED / RETRY_NEVER | FAILED_DEFINITIVE | matrixのexact reason |
| active | exact matrixのEFFECT_POSSIBLE + RETRY_OPERATOR_ACTION | AWAITING_EVIDENCEまたはAWAITING_GRACE | matrixのexact reason、automatic retry 0 |
| active | LOCAL_CANCEL_REQUEST、Bearer send未呼出しまたはdefinite no-send済み、delivery_possible=false | CANCELLED_BEFORE_EFFECT | local dispatch_fencedをFULL commit、NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH、remote message 0 |
| active | LOCAL_CANCEL_REQUEST、delivery_possible=trueまたはsend outcome不明、cancel_state=NONE | current active、cancel_state=PENDING_REMOTE_FENCE | new Application attemptをfenceし、dedicated cancel attempt / record / outbox / send gate=NEVER_INVOKEDをFULL commit。その後だけsame attempt/messageのsend手順へ進む、NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE |
| active | LOCAL_CANCEL_REQUEST、cancel_stateがNONE以外 | currentまたはCANCELLED_BEFORE_EFFECT | new cancel attempt / send 0、persist済みcancel kindを返す |
| active、cancel_state=PENDING_REMOTE_FENCE | REMOTE_CANCEL_RESULT=FENCED_BEFORE_DISPATCH、matching cancel attempt/binding | CANCELLED_BEFORE_EFFECT | NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH、cancel record/resultをcommit |
| active、cancel_state=PENDING_REMOTE_FENCE | REMOTE_CANCEL_RESULT=TOO_LATE_EFFECT_POSSIBLE、matching cancel attempt/binding | AWAITING_EVIDENCEまたはAWAITING_GRACE | dispatch_fencedを維持、NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE |
| any | REMOTE_CANCEL_RESULT、cancel attempt / reverse binding不一致 | current不変 | bounded invalid observation、cancel state / Outcome不変 |
| active、cancel_state=PENDING_REMOTE_FENCE、send gate=NEVER_INVOKEDまたはWOULD_BLOCK_RETRYABLE | fresh TxPermit取得済み、CANCEL_REQUEST send開始前 | current active、cancel_state=PENDING_REMOTE_FENCE、send gate=INVOKED_CLOSED | pre-send FULL commit成功後だけ同じprepared attempt ID / immutable messageでBearerを1回invoke。Commit failure / unknown、またはcommit後send前crashではclosedを維持しsendを推測再実行しない |
| active、cancel_state=PENDING_REMOTE_FENCE | cancel TX_GATE_RESULT=TEMPORARY | current active、same prepared cancel/send gate | fixed backoff後にfresh acquire。new cancel attempt/entropy 0 |
| active、cancel_state=PENDING_REMOTE_FENCE | cancel TX_GATE_RESULT=DENIED/CONTRACT_FENCE | current active、send gate=INVOKED_CLOSED | Bearer send 0、automatic acquire retry 0。CONTRACT_FENCEだけRuntime DEGRADED |
| active、cancel_state=PENDING_REMOTE_FENCE | CANCEL_SEND_RESULT=WOULD_BLOCK definite no-accept | current active、cancel_state=PENDING_REMOTE_FENCE | same attempt ID / immutable messageのsend gate=WOULD_BLOCK_RETRYABLEをFULL commit。Fresh TxPermitでだけ再send可能、new prepare / entropy 0 |
| active、cancel_state=PENDING_REMOTE_FENCE | CANCEL_SEND_RESULT=OK accepted/custody、LOST_UNKNOWN、UNAVAILABLE、DENIED、CORRUPT、invalid EMPTY/partial OK、またはpossible-delivery observation | current active、cancel_state=PENDING_REMOTE_FENCE | send gate=INVOKED_CLOSEDを維持。Result不足 / timeout / restartでreopenせずnew send / attempt 0 |
| active | EFFECT_DEADLINE、effect不可能 | EXPIREDまたはFAILED_DEFINITIVE | deadline規則 |
| active | EFFECT_DEADLINE、effect可能 | AWAITING_GRACE | NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING |
| AWAITING_GRACE | EVIDENCE_CLOSE、required未達 | OUTCOME_UNKNOWN | NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING |
| terminal | VALID_RECEIPT | terminal不変 | late evidence規則だけ適用可能 |
| terminal | REMOTE_CANCEL_RESULT / Disposition / timeout / retry / local cancel | terminal不変 | cached cancel kind / bounded observationだけ、Outcome反転0 |

## Endpoint Delivery reducer

| Current | Input / Guard | Next | Post-commit effect |
| --- | --- | --- | --- |
| ABSENT | valid delivery、capacityあり | INBOX_COMMITTED | RECEIVEDを生成可能 |
| ABSENT | REMOTE_CANCEL_REQUEST、valid binding / dedicated cancel attempt | ABSENT + cancel tombstone | dispatch_fenced + cached CANCEL_RESULT=FENCED_BEFORE_DISPATCHをFULL commit後にreverse send |
| ABSENT + cancel tombstone | later matching APPLICATION ingress | ABSENT + cancel tombstone | inbox / callback 0、cached FENCED_BEFORE_DISPATCHを再送可能 |
| ABSENT | schema/digest/authorization不正 | DISPOSITION_COMMITTED | corresponding Disposition |
| ABSENT | durable inbox / delivery / result capacity不足 | DISPOSITION_COMMITTEDまたはno allocation | exact CAPACITY_EXHAUSTED / NO_EFFECT_PROVEN / RETRY_SAME_AFTER matrix。Disposition record自体も確保不能ならBearer-level no-allocation failure |
| INBOX_COMMITTED | EventFactはno deadline。Commandはtrusted current sampleがdeadline epochと一致かつnow < absolute deadline。token capacityあり、prior invocation count + 1がchecked uint64で表現可能 | DELIVERY_STARTED | context ID = transaction ID、generation = checked prior + 1、completion clock epoch / expiry、bindingをFULL commit後にapplication callback |
| INBOX_COMMITTED | Commandのtrusted current sampleがdeadline epoch不一致、またはnow >= absolute deadline | DISPOSITION_COMMITTED | callbackを呼ばずSTALE_NOT_APPLIEDをFULL commit、positive Receipt 0 |
| INBOX_COMMITTED | transient application/token slot busy | DISPOSITION_COMMITTED | exact APPLICATION_BUSY / NO_EFFECT_PROVEN / RETRY_SAME_AFTER matrix、callback 0 |
| INBOX_COMMITTED | clock port failureまたはNINLIL_CLOCK_UNCERTAINでcompletion expiryを安全に作れない | DISPOSITION_COMMITTEDまたはno allocation | callbackを呼ばずAPPLICATION_BUSYまたはreceiver-unavailable path |
| INBOX_COMMITTED | REMOTE_CANCEL_REQUEST、DELIVERY_STARTED未commit | INBOX_COMMITTED + cancel tombstone | dispatch_fenced + cached CANCEL_RESULT=FENCED_BEFORE_DISPATCHをFULL commit、callback 0 |
| INBOX_COMMITTED | callback invocation count increment不能 | RECOVERY_REQUIRED | callbackを呼ばずNINLIL_REASON_COUNTER_EXHAUSTEDをFULL commit、fail closed / reconcile |
| DELIVERY_STARTED | CALLBACK_COMPLETE + valid APPLIED | RESULT_COMMITTED | result cache + token invalidation + active slot releaseをFULL commit後だけAPPLIED Receipt |
| DELIVERY_STARTED | CALLBACK_COMPLETE + valid VERIFIED | RESULT_COMMITTED | result cache + token invalidation + active slot releaseをFULL commit後だけVERIFIED Receipt |
| DELIVERY_STARTED | callbackがDEFERを返す | DEFERRED_WAIT | 新しいdurable writeなし。callback前commit済みtokenを保持 |
| DELIVERY_STARTED | CALLBACK_COMPLETE + exact matrixのNO_EFFECT_PROVEN Disposition | DISPOSITION_COMMITTED | Disposition + token invalidation + active slot releaseをFULL commit |
| DELIVERY_STARTED | CALLBACK_COMPLETE + exact matrixのEFFECT_POSSIBLE Disposition | DISPOSITION_COMMITTED | effect possible Disposition + token invalidation + active slot releaseをFULL commit、positive Receipt 0 |
| DELIVERY_STARTED | CALLBACK_FATAL | RECOVERY_REQUIRED | token invalidation + active slot release + EFFECT_POSSIBLE + NINLIL_REASON_APPLICATION_FAILEDをFULL commit、health DEGRADED、Receipt 0 |
| DELIVERY_STARTED | unknown callback action、またはCALLBACK_COMPLETE + invalid result | RECOVERY_REQUIRED | token invalidation + active slot release + EFFECT_POSSIBLE + NINLIL_REASON_CALLBACK_CONTRACTをFULL commit、health DEGRADED、Receipt 0 |
| DELIVERY_STARTED | effect後か不明、result未commit | RECOVERY_REQUIRED | Receiptを発行しない |
| DEFERRED_WAIT | DELIVERY_COMPLETE_REQUEST、context ID = transaction ID、exact active generation、token clock epoch / expires-at = durable marker、発行Runtime / delivery / digest binding一致、trusted current sampleが同epochかつnow <= expires-at | RESULT_COMMITTEDまたはDISPOSITION_COMMITTED | result commitとtoken expiry、active slot解放 |
| DEFERRED_WAIT | DEFER_CONTEXT_TIMEOUT、同じtoken generation | RECOVERY_REQUIRED | token expiryとactive slot解放をcommit。Receiptなし |
| expired-token retention中 | DELIVERY_COMPLETE_REQUEST | current不変 | NINLIL_E_INVALID_STATE |
| token record不存在 | DELIVERY_COMPLETE_REQUEST | current不変 | NINLIL_E_NOT_FOUND |
| RECOVERY_REQUIRED | RECONCILE_RESULT=KNOWN_RESULT | RESULT_COMMITTEDまたはDISPOSITION_COMMITTED | known resultをcommit |
| RECOVERY_REQUIRED | RECONCILE_RESULT=REDELIVER | INBOX_COMMITTED | new delivery token generationを準備 |
| RECOVERY_REQUIRED | RECONCILE_RESULT=RETRY_LATER、trusted local clock、descriptor fixed retry_backoffをchecked addition可能 | RECONCILE_WAIT | `retry_not_before = local now + descriptor.retry_backoff_ms`をcommit。out result全体をignore |
| RECOVERY_REQUIRED | RECONCILE_RESULT=OUTCOME_UNKNOWN | DISPOSITION_COMMITTED | OUTCOME_UNKNOWN Disposition、positive Receiptなし |
| RECOVERY_REQUIRED | unknown reconcile action、またはKNOWN_RESULT + invalid result | RECOVERY_REQUIRED | NINLIL_REASON_CALLBACK_CONTRACT、health DEGRADED、result / Disposition / Receipt commit 0、same recovery passの再callback 0 |
| DELIVERY_STARTED、DEFERRED_WAIT、RESULT_COMMITTED、DISPOSITION_COMMITTED、RECOVERY_REQUIRED、RECONCILE_WAIT | REMOTE_CANCEL_REQUEST | current + cancel tombstone | effectを取り消さずcached CANCEL_RESULT=TOO_LATE_EFFECT_POSSIBLEをFULL commit後にreverse send |
| any + cancel tombstone | duplicate REMOTE_CANCEL_REQUEST、same attempt/binding | current | cached CANCEL_RESULTを再送可能、callback / effect 0 |
| RECONCILE_WAIT | RECONCILE_DUE | RECOVERY_REQUIRED | on_reconcileを再実行可能 |
| RESULT_COMMITTED | duplicate same transaction/digest/generation | RESULT_COMMITTED | cached highest Receiptを再発行可能 |
| any existing | duplicate digest conflict | current不変 | INVALID_PAYLOADまたはconflict Disposition |

RECEIVEDはenvelope、schema、payload validation後です。M1a reference portはinbox commit後に発行し、reboot後もduplicateを同じdeliveryへ収束させます。

RECOVERY_REQUIREDからの動作:

- apply contractがabsolute/idempotentなら、同じtransaction IDでcallbackを再実行できます。
- application effectとresultが同じatomic storeにあるなら、そのstoreをreconcileしてRESULT_COMMITTEDへ進めます。
- どちらも証明できなければ、effect certaintyをEFFECT_POSSIBLEとし、APPLIEDを発行しません。
- CALLBACK_FATAL / unknown action / invalid resultのrecovery FULL commit後は、同じRuntime instanceで同Deliveryの`on_delivery`を再呼出しません。Restart / recovery fence後にapply contractに従う`on_reconcile`またはsafe idempotent recoveryだけを許します。
- token invalidation recovery commitがdefinite failureまたはCOMMIT_UNKNOWNでもpositive Receiptを発行せず、deliveryを再dispatchせず、Runtime healthをDEGRADEDにしてstorage recovery後のauthoritative recordへ収束させます。

### Deferred delivery timeout

- Receiver ServiceDescriptorのapplication_completion_timeout_msは1〜`NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS`でなければなりません。
- Runtimeはcallbackを呼ぶ前にnon-zero epochのtrusted local clockをsampleし、同じepoch上でdelivery_started_at_ms + application_completion_timeout_msをchecked additionします。clock uncertain / port failure / overflowではtokenを発行せずcallbackを呼びません。
- callbackごとにprior invocation countをchecked incrementし、1回目をgeneration 1とします。increment不能ならcallbackを呼ばず、NINLIL_REASON_COUNTER_EXHAUSTEDでRECOVERY_REQUIREDへfail closedします。
- callback前のFULL transactionは、DELIVERY_STARTED、context ID = transaction ID、generation = checked invocation count、発行Runtime / transaction / delivery / digest binding、completion clock epoch / completion_expires_at_ms、token activeを含まなければなりません。
- 上記commit成功後だけon_deliveryへcopyable value tokenを渡します。applicationがasync effectを開始した後にtoken identity / expiryを初めてcommitする実装は禁止します。
- callback引数のtoken pointerはcallback中だけborrowedです。DEFERするapplicationは`ninlil_delivery_token_t`のcontext_id / generation / clock_epoch_id / expires_at_msを含むstruct全valueをcopyし、pointerを保持してはなりません。
- callbackがDEFERを返した後は、新しいdurable tokenを作りません。callback前にcommit済みtokenをDEFERRED_WAITとして保持するだけです。
- callbackが同期resultを返した後もcurrent clockをsampleします。trustedかつtoken clock epochと一致し、`now_ms <= token.expires_at_ms`の場合だけresultをcommitできます。expiry超過、epoch change、clock uncertainでは同期resultをsuccessにせずtimeout / RECOVERY_REQUIREDに進みます。exact expiry時刻の同期resultはtimeoutより先にreduceします。
- delivery_completeはowner execution context、callback外、context ID = transaction ID、exact active generation、発行Runtime / delivery / digest bindingがすべて一致するtokenで、current sampleがtrusted、completion clock epochと一致、`now_ms <= completion_expires_at_ms`の場合だけ受理します。別Runtimeに渡したtokenはmatching bindingがないためNINLIL_E_NOT_FOUND、同Runtimeで既知だがactive binding / generationが一致しないtokenはretention規則に従いNINLIL_E_INVALID_STATEです。epoch change、NINLIL_CLOCK_UNCERTAIN、またはRuntime restart後は旧tokenをactiveへ戻さずRECOVERY_REQUIREDに収束させます。
- delivery_completeとtimeoutが同時刻ならdelivery_completeを先に処理します。
- completion成功時はresultとtoken expiryを1つのtransactionでcommitし、active token resourceを解放します。
- timeout時はtoken expiry、NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT、RECOVERY_REQUIREDを1つのtransactionでcommitし、active token resourceを解放します。
- active token slotを解放しても、result / Dispositionまたはreconcileが完了するまでdelivery reservationは解放しません。
- expired token recordは12章のrequired_dedup_window_ms / result-cache retention contractでboundedに保持します。retention中のlate delivery_completeはNINLIL_E_INVALID_STATE、retention終了後はNINLIL_E_NOT_FOUNDです。
- expired token recordはstate変更やapplication result読取りを行いません。
- context ID / generationの組を再利用してはなりません。clock epoch / expires-atだけを書き換えて同じidentityとすることも禁止します。Active token countがmax_deferred_tokensへ達する前に新規DeliveryをAPPLICATION_BUSYで拒否します。

### on_reconcile reducer

RECOVERY_REQUIREDへcommitした後だけon_reconcileを呼びます。callback自体をsuccess evidenceとして扱いません。

Deliveryはdurable `reconcile_retry_generation`を持ち、最初にRECOVERY_REQUIREDへ入るcommitで1を設定します。同じgenerationのcallback中crash/commit failureはgenerationを進めず再実行でき、restartでも値を保持します。`RETRY_LATER` result commitだけがchecked +1したnext generationとnot-beforeをatomic保存し、due後のcallbackはそのgenerationを使います。MAXでRETRY_LATERを受けた場合はtimer/callback cursor successを作らずCOUNTER_EXHAUSTED markerをcommitしてRECOVERY_REQUIREDに留まります。KNOWN_RESULT、OUTCOME_UNKNOWN、REDELIVER成功はreconcile workを終了し、別のindependent recovery episodeが同Deliveryに再発しない限りgenerationを再初期化しません。

| Action | Guard / durable transition | Result |
| --- | --- | --- |
| KNOWN_RESULT | out_known_result valid。result cache / DispositionをFULL commit | positiveならReceipt、negativeならDisposition |
| REDELIVER | apply contractがIDEMPOTENTまたはapplication dedup対応。checked next callback invocation countをnew delivery token generationとしてcommit | on_deliveryを再実行。旧tokenはexpired |
| RETRY_LATER | trusted local clockからdescriptor fixed `retry_backoff_ms`だけでinternal not-beforeをchecked導出可能 | RECONCILE_WAIT。out result全体をignore |
| OUTCOME_UNKNOWN | effect可能性とunknown DispositionをFULL commit | positive Receiptなし |

- REDELIVERで同じtransaction / event IDとpayload digestを維持し、delivery invocation countとtoken generationをchecked incrementします。increment不能ならcallbackを呼ばず、RECOVERY_REQUIRED + NINLIL_REASON_COUNTER_EXHAUSTEDに留めてKNOWN_RESULTまたはOUTCOME_UNKNOWNによるreconcileを必要とします。
- RETRY_LATERはApplication指定`retry_delay_ms`を読みません。local nowの取得失敗 / uncertain、epoch guard不成立、または`now_ms + descriptor.retry_backoff_ms`のchecked addition overflowではnew timerを作らず、clock uncertain / counter exhaustedとしてfail closedします。
- on_reconcile中にcrashした場合、RECOVERY_REQUIREDまたはRECONCILE_WAITのdurable stateから再実行します。
- KNOWN_RESULTのcommit acknowledgement不明ではReceiptを発行せず、storage recovery後にresult cacheを読み直します。

## Receipt reducer

VALID_RECEIPTは、Coreがtransaction / target / issuer / self-contained service identity / content / generation bindingとstageを検査済みのinputです。

M1a internal `evidence_digest`は、Receiptまたはapplication resultの**exact evidence bytes**に対する`SHA-256(exact evidence bytes)`です。evidence length 0もSHA-256(empty)として導出し、zero digestと同一視しません。これはdedup / summary / audit用にCoreが導出するinternal valueであり、wire Receiptまたはpublic `ninlil_application_result_t`にapplication申告の独立hash fieldを要求しません。Applicationが別hashを申告したと推測してはなりません。

| Guard | 動作 |
| --- | --- |
| transaction、target、issuer、service identity、content digest/generation不一致 | state変更なし、bounded invalid counter |
| exact duplicate | state/Outcome/spool revision変更なし、duplicate counterとrecord revisionだけをsaturating更新 |
| current highestより低いstageのnew material | highest/latest/state不変。raw空きまたはsummary overflowへmaterial/countをcommit |
| current highestと同じstageのnew material | highest/state不変。durable ingress sequenceが新しいmaterialをlatest fieldsへcommit |
| currentより高いstage | highest_receipt_stageとlatest_evidence_stage、latest fieldsをcommit |
| required stage到達、PROVEN_IN_TIME、non-terminal | SATISFIEDへcommit |
| required stage到達、PROVEN_LATE、non-terminal | latest evidenceとEXPIRED / NINLIL_REASON_REQUIRED_EVIDENCE_LATEを同じtransactionでcommit |
| required stage到達、TIME_UNKNOWN、non-terminal | latest evidenceをcommit。evidence closeでOUTCOME_UNKNOWN |
| required stage到達、terminal | terminal不変、late evidenceをcommit |
| required stage未達 | active stateまたはterminal不変 |

Receipt処理のstorage commitが失敗または不明なら、Receiptを処理済みとACKしてはなりません。durable ingress copyを保持して再処理します。

### Evidence detail上限

`L = runtime_config.max_evidence_per_target`（1..8）とします。これはtargetごとのraw evidence detail上限であり、`L + 1`件目以後のvalid Receiptを捨てる許可ではありません。

Admission時に、raw detail `L`件とは別に固定長evidence summary recordを1件確保します。Public EVIDENCE accountingはtargetごとにsummary 1 + raw `L`の`L + 1` slotsで、admission commit直後はsummary used=1、raw reserved=`L`です。Summaryは最低限、次を持ちます。

- highest_receipt_stage
- latest_evidence_stage
- latest issuer identity
- latest materialのdurable ingress sequence、`evidence_time` / Controller durable ingress time。clock epoch / now / trustを含むvalue copy
- latest bounded evidence dataとそのdigest
- late_evidence_present
- valid material count
- exact duplicate count
- raw detail overflow count
- late evidence count
- counter_saturated flag

Receipt分類:

- exact duplicate: transaction、target、issuer、service identity、stage、content/generation、derived evidence digest、exact evidence bytes、`evidence_time`のepoch / now / trustが全て一致。
- new material: 上記exact tupleのいずれかが異なるvalid Receipt。Evidence timeを大小比較してidentityや順序を決めません。
- lower-stage material: stageは低いがexact duplicateではない。

Atomic update:

1. raw detailが`L`件未満でnew materialならraw detailを追加する。Lower-stage new materialも含む。
2. raw detailが`L`件でもvalid higher-stage / new materialを拒否しない。
3. `highest_receipt_stage = max(previous, material stage)`とする。Public `latest_evidence_stage`はこのmonotonic highestと常に一致する。Material stageがnew highest、またはcurrent highestと同じでdurable ingress sequenceが大きい場合だけ、latest issuer/time/data/digest/sequenceをそのmaterialへ更新する。Lower-stage new materialはlatest fieldsを巻き戻さない。
4. exact duplicateはduplicate count、rawに入らないnew materialはoverflow countを増やす。
5. terminal Outcomeは変更しない。

New materialをrawへ追加すると1 slotだけreserved→usedへ移し、raw `L`件後はsummary updateだけでslot数を変えません。Terminal commitはunused raw reservationを解放せず、summary/raw usedとともにtransaction evidence retention cleanupまで保持します。Summary + raw L cellは12章どおり最大encoded sizeでadmission時にphysical materializeし、replacement用journal headroomもpreallocateします。したがってunrelated workで後からStorageがfullでも、admitted transactionのlate materialは残るraw cellまたは既存summary replacementへ記録できます。Storage I/O/corruption/commit unknownは別のfail-closed pathです。SummaryはTRANSACTIONへ暗黙内包せず、EVIDENCEの`+1` unitとして12章limitへ含めます。

Counterはchecked uint64です。increment不能時はUINT64_MAXを維持してcounter_saturated=trueをcommitし、Receipt自体のhighest/latest/late情報は処理します。

Summary updateのstorage commitに失敗した場合、Receipt ingressを保持して再処理します。raw detail fullをNINLIL_REASON_CAPACITY_EXHAUSTEDとしてReceipt issuerへ返したり、valid higher stageを失ってはなりません。

## Delivery Dispositionとretry

Dispositionはattempt-scopedです。attempt IDがcurrentでも過去のknown attemptでもない場合は無効です。過去attemptのDispositionはObservationとして保存できますが、current attemptを失敗させません。

### Effect certainty

Dispositionは次のどちらかを必須とします。

- NO_EFFECT_PROVEN
- EFFECT_POSSIBLE

effect certaintyがないDispositionから、FAILED_DEFINITIVEを導いてはなりません。

### Exact Disposition matrix

APP_RESULT_POSITIVE_EVIDENCEはevidence_stageがserviceのsupported non-zero stage、Disposition NONE、reason NONE、effect certainty NONE、retry guidance NEVER、retry_delay_ms=0、evidence 0〜128 bytesのexact combinationだけを受理します。

Application resultとBearer `DISPOSITION`は次のexact combinationだけを受理します。`max` = NINLIL_M1A_MAX_RETRY_DELAY_MSです。

| Disposition | Effect certainty | Retry guidance | Public reason | retry_delay_ms |
| --- | --- | --- | --- | ---: |
| RETRY_LATER | NO_EFFECT_PROVEN | RETRY_SAME_AFTER | NINLIL_REASON_RECONCILE_RETRY_LATER | 0〜max |
| INVALID_PAYLOAD | NO_EFFECT_PROVEN | RETRY_MODIFIED | NINLIL_REASON_APPLICATION_FAILED | 0 |
| UNSUPPORTED_SCHEMA | NO_EFFECT_PROVEN | RETRY_MODIFIED | NINLIL_REASON_APPLICATION_FAILED | 0 |
| UNAUTHORIZED_SERVICE | NO_EFFECT_PROVEN | RETRY_MODIFIED | NINLIL_REASON_TARGET_UNAUTHORIZED | 0 |
| STALE_NOT_APPLIED | NO_EFFECT_PROVEN | RETRY_NEVER | NINLIL_REASON_APPLICATION_FAILED | 0 |
| APPLICATION_BUSY | NO_EFFECT_PROVEN | RETRY_SAME_AFTER | NINLIL_REASON_RECEIVER_UNAVAILABLE | 0〜max |
| APPLY_FAILED | NO_EFFECT_PROVEN | RETRY_SAME_AFTER | NINLIL_REASON_APPLICATION_FAILED | 0〜max |
| APPLY_FAILED | EFFECT_POSSIBLE | RETRY_OPERATOR_ACTION | NINLIL_REASON_APPLICATION_FAILED | 0 |
| VERIFY_FAILED | EFFECT_POSSIBLE | RETRY_OPERATOR_ACTION | NINLIL_REASON_APPLICATION_FAILED | 0 |
| CAPACITY_EXHAUSTED | NO_EFFECT_PROVEN | RETRY_SAME_AFTER | NINLIL_REASON_CAPACITY_EXHAUSTED | 0〜max |
| OUTCOME_UNKNOWN | EFFECT_POSSIBLE | RETRY_OPERATOR_ACTION | NINLIL_REASON_OUTCOME_UNKNOWN | 0 |

Table外のcertainty / guidance / reason / delayの組み合わせはNINLIL_REASON_CALLBACK_CONTRACTです。Positive Receiptを生成せず、Endpoint Deliveryではtoken invalidation + slot release + RECOVERY_REQUIRED / EFFECT_POSSIBLEをFULL commitします。Bearer ingressではinvalid inputとしてcurrent targetを変更しません。

DesiredState reducerはmatrixを次のように適用します。

- NO_EFFECT_PROVEN + RETRY_SAME_AFTERだけが通常のautomatic retry候補です。budget、dispatch fence、trusted clock epoch、derived not-before < deadlineがすべて成立した場合だけinternal RETRY_WAIT / public WAITING_WINDOWへ進みます。
- NO_EFFECT_PROVEN + RETRY_MODIFIEDまたはRETRY_NEVERは現在Submissionの自動再送を行わずFAILED_DEFINITIVEです。
- EFFECT_POSSIBLE + RETRY_OPERATOR_ACTIONはautomatic retryせずAWAITING_EVIDENCEまたはAWAITING_GRACEです。Required evidence未到達なevidence closeはOUTCOME_UNKNOWNです。
- NO_EFFECT_PROVENでretry budgetを使い切った場合はFAILED_DEFINITIVE / NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT、EFFECT_POSSIBLEではそのreasonを使わずOUTCOME_UNKNOWNへ収束させます。

EventFactはrequired Receipt / explicit discard前にDispositionだけでpayloadを解放またはterminal Outcome化しません。RETRY_SAME_AFTERはcurrent 8-attempt cycle内の次attemptですが、CAPACITY_EXHAUSTED / NO_EFFECT_PROVENだけはdownstream capacity improvement待ちとして即時PARKED_RETRY + NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLEです。RETRY_MODIFIED / RETRY_NEVER / RETRY_OPERATOR_ACTIONはPARKED_RETRY + NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATIONです。Public park reasonは常にNINLIL_REASON_EVENT_RETRY_CYCLE_PARKEDのままです。

### Relative retry delayのnormalize

Public ABI、Bearer、application result、origin authorization decisionは`retry_delay_ms`だけを運び、remote absolute not-beforeを運びません。valid rangeは0..NINLIL_M1A_MAX_RETRY_DELAY_MSです。`retry_delay_ms == 0`は入力元がdelayを指定しないことを意味し、retryableでないresult / Dispositionでは0必須です。例外として`on_reconcile`のaction `RETRY_LATER`はout result全体をignoreし、descriptor fixed backoffだけを使います。

Retryable inputを受けたRuntimeは、reducer inputとして固定したtrusted local clock sampleから次を導出します。

    effective_retry_delay_ms = max(profile.retry_backoff_ms, input.retry_delay_ms)
    retry_not_before_ms = checked(local_now.now_ms + effective_retry_delay_ms)

`retry_not_before_ms`とlocal clock epochはinternal timer stateとして同じFULL transactionにcommitします。これをremote申告absolute timeとmax比較してはなりません。M1aはexponential backoffやjitterを追加しません。local clock failure / uncertain、checked addition overflow、または後のclock epoch不一致では、数値比較やdispatchを行わずclock-uncertain / counter-exhausted recoveryへ進みます。

### DesiredStateCommand retry budget

- attempt budgetはATTEMPT_PREPARED commit時に1消費します。
- crash、send result不明、carrier observationだけを理由にbudgetを戻してはなりません。
- Accepted-send ATTEMPT_RECEIPT_TIMEOUTはEFFECT_POSSIBLEであり、NO_EFFECT_PROVENやRETRY_SAME_AFTER guidanceを生成しません。TargetはAWAITING_EVIDENCEを保ちます。
- EFFECT_POSSIBLEのままautomatic retryを許すsafe apply-contract guardは、descriptorがAPPLY_IDEMPOTENTで同じabsolute desired stateを再適用するか、APPLY_APPLICATION_DEDUPで同じtransaction / target / generation / content digestとrequired durable dedup windowを維持する場合だけです。どちらもnew business identityを作りません。
- 上記guardに加え、dispatch_fenced=false、required evidence未到達、budget残あり、trusted deadline epoch、`checked(now + retry_backoff_ms) < effect_deadline_at`がすべて成立した場合だけnew attemptを作れます。不成立ならsend 0でevidence closeまで待ちます。
- Exact Disposition matrixのNO_EFFECT_PROVEN + RETRY_SAME_AFTERは別のautomatic retry pathで、internal RETRY_WAIT / public WAITING_WINDOWを使います。
- internal retry_not_beforeは上記formulaで一度だけ導出します。
- timer epochがdeadline_clock_epoch_idと一致し、internal retry_not_beforeがeffect_deadline_at未満の場合だけ再dispatchできます。
- NO_EFFECT_PROVENでbudgetを使い切った場合はFAILED_DEFINITIVE、reasonはNINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECTです。
- EFFECT_POSSIBLEでbudgetを使い切った場合はAWAITING_GRACE、その後OUTCOME_UNKNOWNです。
- restartでattempts_usedを0へ戻してはなりません。

### EventFact retry cycle

- 1 cycleは8 attemptsです。
- retry、new retry cycle、restartのすべてでevent IDとcaller idempotency keyを不変に保ち、new key aliasを作りません。
- attempts_in_cycleはATTEMPT_PREPARED commit時に1増やします。
- crash、send result不明、timeout、carrier observationでattempts_in_cycleを戻してはなりません。
- attempts_in_cycleが8に達し、required Receipt未到達ならPARKED_RETRYへ進みます。Public reasonはNINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、internal event_park_causeはNINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENTです。Tx Gate TEMPORARYは8thまでfixed-backoff cycle内retryで、このruleを使います。
- Application Bearer sendのWOULD_BLOCK/UNAVAILABLEはdefinite no-sendでも改善機会をBearer availability epochへbindするため、1〜8件のpartial cycleを即時closeしPARKED_RETRY / BEARER_UNAVAILABLEへ進みます。ATTEMPT_PREPAREDで増えたattempt countを戻しません。DENIEDはPARKED_RETRY / APPLICATION_REMEDIATIONです。
- Valid remote CAPACITY_EXHAUSTED / NO_EFFECT_PROVEN DispositionはPARKED_RETRY / CAPACITY_UNAVAILABLEです。Admission resource不足、Storage failure、step budget不足はこのcauseを生成しません。
- PARKED_RETRYはactive transactionです。Timer、retry/Disposition、clock uncertaintyだけではFAILED_DEFINITIVE、EXPIRED、OUTCOME_UNKNOWNへ進めません。Required ReceiptはSATISFIED + RELEASED、監査付きexplicit discardだけはFAILED_DEFINITIVE + DISCARDEDへ進めます。
- Dispositionを受けてもpayloadを解放せず、public reasonをNINLIL_REASON_EVENT_RETRY_CYCLE_PARKEDに保ち、matrixに従うinternal event_park_causeを付けてPARKED_RETRYへ進めます。
- PARKED_RETRY中はtimerだけでattemptを開始しません。
- valid required Receiptはpark中でも受理し、SATISFIED + RELEASEDへ進めます。

### Fresh Bearer availability epoch

AVAILABILITY_EPOCH_AVAILABLEはBearer provider所有のnon-zero strictly monotonic `availability_epoch`です。`available`の0↔1変化ごとにchecked incrementし、available=1のままでもsend queue full / WOULD_BLOCK→space available等、以前blockしたworkの成功可能性が実際に改善したtransitionではincrementします。Poll、send success、bitも改善条件も同一の通知、Runtime restartでincrementしません。

Provider / harnessはcurrent epoch、available bit、blocked historyをrestartを跨いで保持し、完全なprovider namespace resetだけが新namespaceにできます。Increment不能でwrapせず、Bearerをunavailable / fatalにします。同じepochでavailable bitを変更したtupleはprovider contract failureです。

- `runtime_step` entryのBearer state pollでvalid strictly larger epochを観測したら、namespace-level `latest_availability_epoch + available flag + observation clock epoch/time`だけを`runtime.before_bearer_state_commit` / `after`間の1 FULL transactionへcommitします。Bearer state observationはdurable reducer ingressではないためordered-input sequenceとscheduler ownerを消費しません。このcommitはEvent recordを一括更新せず、state-transition budgetをexactly 1消費します。Exact same epoch/flagとold epochはwrite/hook 0、same epoch/different flagはcontract failureでstate不変/resume 0です。
- EventFactがPARKED_RETRYへ入るFULL commitは、その時点のnamespace latest epochを`last_seen_availability_epoch`へsnapshotします。Active Eventへepochをfan-outせず、後からparkしたEventが古い改善通知を使ってresumeすることを防ぎます。
- Namespace stateが`available=1`で、latest epochがparked Eventの`last_seen_availability_epoch`と`last_consumed_availability_epoch`の両方よりstrictly大きく、causeがNINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT、NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE、NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLEのいずれかなら、そのEvent ownerへ12章work kind `AVAILABILITY_CONSUME`を1件作ります。Owner sequence昇順でEventごとにseparate FULL commitし、completed cycle summary、new retry_cycle_id、attempts_in_cycle=0、last seen/consumed epoch、spool revisionをatomic更新します。
- 1 Event commitはstate-transition budget 1です。N Eventsを1巨大transactionや1 counterへまとめず、budget/crashで途中停止してもnamespace observationとcommit済みEventだけを保持し、残りは次stepで同じepochをexactly once consumeします。Cursorとのall-or-noneは12章11.0に従います。新capacity reservationは不要です。
- PARKEDでないEvent、APPLICATION_REMEDIATION、COUNTER_EXHAUSTEDにはavailability candidateを作りません。前者が後でPARKEDへ入る場合、そのpark commitでcurrent latest epochをseenへsnapshotします。Application/counter causeのexplicit management/Receipt/discard規則は変えません。
- input epochがnamespace latest以下、またはEventのseen/consumed以下ならNINLIL_REASON_STALE_AVAILABILITY_EPOCHとしてno-opです。
- NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATIONはavailability epochだけでresumeせずexplicit resumeを要求します。NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTEDはrequired Receiptまたはdiscardだけを許します。
- commit後にHELD_READYへ進み、通常schedulerがdispatchします。
- epoch signalはremote capacity reservationではなく、再試行を許すfresh availability evidenceです。admission assuranceのremote_capacity_reservedはfalseのままです。
- 同じepochのduplicateでcycleを複数回resetしてはなりません。
- Runtime `ninlil_capacity_entry_t.capacity_epoch`はresourceごとの別observability domainです。Bearer availability_epochと数値比較、代入、max/min、resume input化してはなりません。

### Operator resume

operator resumeはPARKED_RETRYを新しいcycleへ戻す明示management operationです。

- requestはnon-zero operation_id / actor_id、exact expected_spool_revision、known resume_reason、1〜128 byte audit_metadataを持ちます。
- ABI / null / syntaxとtransaction identity / familyの検証後、current stateやexpected revisionより先にresume / discard両ledgerからoperation IDをlookupします。
- same operation kind + same canonical request digestがあれば、current state / revisionが後で変わっていてもpersist済みresultとそのoperation時のcycle / spool revisionを返し、cycleを再度増やしません。
- operation IDがありdigestまたはoperation kindが異なればNINLIL_EVENT_RESUME_CONFLICTです。この場合current state / revisionを評価しません。
- unseen operationだけcurrent state、expected spool revision、resume ledger limit、operation-specific guardの順で評価します。Active、RELEASED、DISCARDED、別familyもAPI invocation errorではなくNINLIL_OKとexact result kindを返します。
- 8個のdistinct resume operationを使用後、9個目のunseen IDはNINLIL_EVENT_RESUME_LIMIT_EXHAUSTED / NINLIL_REASON_CAPACITY_EXHAUSTEDで、state、spool revision、cycle、ledgerを変更しません。既存8 IDのreplayはretention中引き続可能です。
- completed cycle summary、operation mapping / audit、new retry_cycle_id、attempts_in_cycle=0、spool_revision incrementをatomic commitしてからHELD_READYへ進みます。
- storage不足またはcommit不明時はPARKED_RETRYのpayloadを保持します。
- event_park_causeがNINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTEDの場合はresumeせず、required Receiptまたはdiscardだけを許します。
- known resume_reasonはaudit分類でありpark causeとのmatching guardではありません。COUNTER_EXHAUSTED以外のPARKED_RETRYでは5つのknown reasonをすべて受理でき、RESUME_TESTも特別なcause制約を持ちません。
- unseen operationでcurrent stateがPARKED_RETRYかつevent_park_cause=COUNTER_EXHAUSTEDなら、expected revision/ledger limitより先にNINLIL_EVENT_RESUME_NOT_RESUMABLE / NINLIL_REASON_COUNTER_EXHAUSTEDを返します。Request operation IDとcurrent retry_cycle_id/spool_revisionをechoし、ledger slot、state、revision、resource、metricsを変更しません。

successはNINLIL_EVENT_RESUME_RESUMED、idempotent replayはNINLIL_EVENT_RESUME_ALREADY_RESUMEDです。Commit unknownはNINLIL_E_STORAGE_COMMIT_UNKNOWNでresult kind INVALIDです。同じoperation ID / requestで再試行し、既存commitまたは新しい1回のresumeへ収束させます。

## Cancel

### DesiredStateCommand cancel

Remote cancelはApplication attemptと別のprotocolです。Command admission時にControllerは自身のcancel record/outbox metadataをlocal reserveし、Endpointは自身のinbound resource計算でcancel tombstone/result capacityを確保します。Controller admission assuranceがremote Endpoint capacityをreserveしたことにはなりません。1 transactionにつきdedicated non-zero cancel attempt ID / prepared record / entropy allocationはexactly 1つです。Cancel IDもAttempt ID allocationのmax-4 entropy / collision規則に従い、取得失敗ではcancel record / send 0、NINLIL_E_ENTROPYです。Application attempt IDをcancel IDとして再利用しません。Bearer send invocationだけは下記WOULD_BLOCK ruleの範囲でsame attempt/messageを再実行できます。

- Bearer send未呼出しまたはdefinite no-sendが確定し、delivery_possible=falseなら、Controllerはlocal dispatch fenceをFULL commitしてFENCED_BEFORE_DISPATCH / NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH、Outcome=CANCELLED_BEFORE_EFFECTとします。Remote cancelは送りません。
- Delivery possibilityが一度でも生じた、またはsend outcomeが不明なら、Controllerはnew Application attemptをfenceし、dedicated cancel attempt / record / outboxをFULL commitした後だけforward CANCEL_REQUESTを送ります。Synchronous API resultはPENDING_REMOTE_FENCE / NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCEです。
- Prepared cancel recordのdurable send gateはNEVER_INVOKED / WOULD_BLOCK_RETRYABLE / INVOKED_CLOSEDだけです。First sendはNEVER_INVOKED、retry sendはWOULD_BLOCK_RETRYABLEからだけ開始します。各sendはfresh TxPermit取得後かつBearer call前にINVOKED_CLOSEDを、12章17節の`controller.before_cancel_send_gate_commit` / `controller.after_cancel_send_gate_commit`を通るFULL commitで固定し、成功確認後だけinvokeします。このcommitが失敗/unknown、またはcommit後send前にcrashした場合はINVOKED_CLOSEDを維持し、送信したかを推測して再実行しません。
- Bearer `send(CANCEL_REQUEST)`をsame prepared attempt ID / immutable messageで再実行できるのは、直前のinvocationがdefinite no-acceptのWOULD_BLOCKを返し、そのobservationをWOULD_BLOCK_RETRYABLEへFULL commitできた場合だけです。未消費の旧permitをcontractどおりreleaseし、各retryはfresh TxPermitを取得します。再びWOULD_BLOCKなら同じruleを繰り返せます。New cancel attempt / entropy / prepared recordは作りません。
- OK accepted/custody、LOST_UNKNOWN、UNAVAILABLE、DENIED、CORRUPT、invalid EMPTY/partial OK、またはEndpointへ届いた/フェンスが作用した可能性のobservationではsend gateをINVOKED_CLOSEDのまま保持します。Closed後はCANCEL_RESULT不足、timeout、restartでreopenせず、new send / attempt 0のPENDING_REMOTE_FENCEです。CANCEL_RESULT不足だけでno-effectを主張しません。
- EndpointはABSENTまたはINBOX_COMMITTEDかつDELIVERY_STARTED未commitの場合だけ、cancel tombstone + dispatch fence + cached FENCED_BEFORE_DISPATCH resultをFULL commitします。後着APPLICATIONもcallbackしません。
- EndpointがDELIVERY_STARTED、active/expired token、result/Disposition、RECOVERY_REQUIRED、またはeffect possibilityを一度でもdurable記録済みなら、effectを戻さずTOO_LATE_EFFECT_POSSIBLEをcache/sendします。
- Duplicate same cancel attempt / exact bindingはcached resultを再送し、application callback、tombstone、effect、cancel attemptを追加しません。Cancel record/resultはtransaction terminal retentionまで保持します。
- Controllerのmatching CANCEL_RESULT=FENCED_BEFORE_DISPATCHはCANCELLED_BEFORE_EFFECTへFULL commitします。TOO_LATE_EFFECT_POSSIBLEはdispatch fenceを維持してAWAITING_EVIDENCE / AWAITING_GRACEへ進み、evidence closeまで不明ならOUTCOME_UNKNOWNです。
- 同じlogical timeのdurable-ingress済みvalid required ReceiptとCANCEL_RESULTはReceiptが先です。Receiptがすでにterminal successをcommitした場合、cancel resultでOutcomeを反転しません。それ以外の同priority競合はdurable ingress sequenceで決定します。
- Repeated public cancel APIはnew attempt/sendを作らずpersist済みcurrent cancel kindを、12章のall-field matrixどおり返します。Persist済みcancel kind lookupはcurrent terminal checkより先で、cancel recordなしでtransactionが先にterminalの場合だけALREADY_TERMINALです。Cancelは既に起きたeffectを戻しません。

### EventFact cancel

EventFactは既に発生した事実なのでcancelできません。

- M1aではEventFactへのcancel_requestはNINLIL_E_UNSUPPORTEDです。stateとspoolは不変で、診断reasonはNINLIL_REASON_EVENT_FACT_IMMUTABLEです。
- EventFactがterminalでもcancel_requestはNINLIL_E_UNSUPPORTEDです。
- cancel_requestはspool、payload、retry stateを削除しません。

### Explicit discard

M1aはcancelと別に、次のpublic management APIを実装します。

    ninlil_event_resume(runtime, transaction_id, request, out_result)
    ninlil_event_discard(runtime, transaction_id, request, out_result)

discard requestは最低限、次を持ちます。

- non-zero operation_id / actor_id / expected_event_id
- matching expected_content_digest
- exact expected_spool_revision
- known discard_reason
- acknowledge_required_receipt_absent = 1
- 1〜128 byte audit_metadata

DiscardもOperator resumeと同じmanagement guard precedenceを使います。Resume / discard両ledgerのoperation ID lookupがcurrent state / expected revisionより先です。Same discard operation + same canonical request digestはpersist済みALREADY_DISCARDED、same IDでdigestまたはoperation kindが異なればNINLIL_EVENT_DISCARD_CONFLICTで、どちらもrevision guardを再評価しません。Unseen operationだけcurrent state、expected revision、discard-specific guardの順で評価します。

discard commitは次を1つのstorage transactionで行います。

- discard audit record
- event identityとpayload digestを残すtombstone
- operation ID、actor、discard reason、audit metadata、trusted audit時刻
- highest Receipt、retry cycle、cumulative attempts
- delivery_possible
- transaction terminal Outcome = FAILED_DEFINITIVE
- terminal reason = NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
- spool state = DISCARDED
- payload解放

commit成功前にpayloadを削除したりDISCARDEDを返してはなりません。

discard result:

- successはNINLIL_EVENT_DISCARD_DISCARDED、reason NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT、spool_released=1
- same operation ID / same canonical request digestはNINLIL_EVENT_DISCARD_ALREADY_DISCARDED。payloadを二重解放しない
- required Receiptが先ならNINLIL_EVENT_DISCARD_ALREADY_RELEASED
- wrong familyはNINLIL_EVENT_DISCARD_NOT_EVENT_FACT
- same operation ID / different digestはNINLIL_EVENT_DISCARD_CONFLICT、reason NINLIL_REASON_DISCARD_CONFLICT
- revision mismatchはNINLIL_EVENT_DISCARD_STALE_SPOOL_REVISION、reason NINLIL_REASON_STALE_SPOOL_REVISION
- definite storage failureはNINLIL_E_STORAGE、commit不明はNINLIL_E_STORAGE_COMMIT_UNKNOWN。result kind INVALID、spool_released=0

valid required Receiptとdiscardが同時刻ならReceiptを先にcommitします。EventFactはSATISFIED + RELEASEDとなり、discard resultはNINLIL_EVENT_DISCARD_ALREADY_RELEASEDです。

discardが先にcommitされた後でrequired Receiptが到着した場合、terminal OutcomeはFAILED_DEFINITIVEのままです。Receiptはlate evidenceとして記録し、payloadを復元しません。

## EventFact reducer

### Origin admission

| Current | Input / Guard | Next | Result |
| --- | --- | --- | --- |
| no record | valid EventFact、provider ALLOW、grant binding/expiry/limits guard成功、capacityあり | HELD_READY | ADMITTED_READY |
| no record | spool/storage capacity不足 | no record | REJECTED / NINLIL_REASON_CAPACITY_EXHAUSTED |
| no record | next transaction_sequence increment不能 | no record | REJECTED / NINLIL_REASON_COUNTER_EXHAUSTED。既存record不変 |
| no record | grant missing / denied / binding mismatch | no record | REJECTED / NINLIL_REASON_GRANT_INVALID |
| no record | grant expired | no record | REJECTED / NINLIL_REASON_GRANT_EXPIRED |
| no record | target authorization mismatch | no record | REJECTED / NINLIL_REASON_TARGET_UNAUTHORIZED |
| no record | grant limit超過 | no record | REJECTED / NINLIL_REASON_GRANT_LIMIT_EXCEEDED |
| no record | grant provider TEMP failure | no record | NINLIL_E_WOULD_BLOCK + NINLIL_SUBMISSION_INVALID / NINLIL_REASON_NONE。health cause add 0 |
| no record | grant provider PERMANENT failure / invalid decision | no record | NINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALID / NINLIL_REASON_NONE。Runtime degraded cause NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLEをadd |
| existing same caller key / same digest / same event ID | existing state | existing | ALREADY_ADMITTED |
| existing same caller key / same digest / different event ID | existing state | existing | IDEMPOTENCY_CONFLICT。event alias mapping追加0 |
| existing same caller key / different digest | existing state | existing | IDEMPOTENCY_CONFLICT |
| existing same event ID / same canonical digest / same caller key | existing state | existing | ALREADY_ADMITTED |
| existing same event ID / same canonical digest / different caller key | existing state | existing | IDEMPOTENCY_CONFLICT。alias mapping追加0 |
| existing same event ID / different canonical digest | existing state | existing | IDEMPOTENCY_CONFLICT |

local admissionがREJECTEDまたはstorage errorの場合、NinlilはEventFactを所有しません。source applicationは同じevent identityとidempotency keyを保持し、product固有local fail-safeを実行しなければなりません。

Provider API errorではassuranceもzeroです。Permanent/invalid responseでaddしたNINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE causeは後続valid provider evaluationでclearし、temporary failureではhealth multisetを変更しません。

### Spool delivery

| Current | Input / Guard | Next | Effect / Result |
| --- | --- | --- | --- |
| HELD_READY、RETRY_WAIT | DISPATCH_DUE、attempts_in_cycle < 8、internal retry timerなしまたはtrusted current sampleが同じlocal epochでnot-before到達、max 4 draw内でunique non-zero attempt ID取得 | ATTEMPT_PREPARED | attempt index / record / attempts_in_cycle incrementをFULL commit |
| HELD_READY、RETRY_WAIT | attempt ID max 4 draw failure | current | NINLIL_E_ENTROPY、NINLIL_REASON_OUTCOME_UNKNOWN entropy health causeをadd、attempt / cycle count / permit / send 0 |
| ATTEMPT_PREPARED | TX_GATE_RESULT=OK-valid | ATTEMPT_PREPARED | valid permit取得後だけBearer send |
| ATTEMPT_PREPARED | TX_GATE_RESULT=TEMPORARY、attempts_in_cycle < 8 | RETRY_WAIT | NO_EFFECT_PROVEN、Receipt timeout 0、fixed backoff |
| ATTEMPT_PREPARED | TX_GATE_RESULT=TEMPORARY、attempts_in_cycle == 8 | PARKED_RETRY | CYCLE_EXHAUSTED_TRANSIENT、payload保持 |
| ATTEMPT_PREPARED | TX_GATE_RESULT=DENIED/CONTRACT_FENCE | PARKED_RETRY | APPLICATION_REMEDIATION、Bearer send 0。CONTRACT_FENCEだけRuntime DEGRADED |
| ATTEMPT_PREPARED | BEARER_RESULT=OK accepted/custody or LOST_UNKNOWN | AWAITING_RECEIPT | send observation timeにbindしたATTEMPT_RECEIPT_TIMEOUT、delivery_possible=true、observation+cursorをFULL commit |
| ATTEMPT_PREPARED | BEARER_RESULT=WOULD_BLOCK/UNAVAILABLE | PARKED_RETRY | NO_EFFECT_PROVEN、Receipt timeout 0、permit release、partial cycle close、BEARER_UNAVAILABLE、observation+cursorをFULL commit |
| ATTEMPT_PREPARED | BEARER_RESULT=DENIED | PARKED_RETRY | NO_EFFECT_PROVEN、permit release、APPLICATION_REMEDIATION、observation+cursorをFULL commit |
| ATTEMPT_PREPARED | BEARER_RESULT=CORRUPT/EMPTY/unknown/invalid OK output | AWAITING_RECEIPT | EFFECT_POSSIBLE、send observation timeからtimeout、permit release 0、Runtime DEGRADED、observation+cursorをFULL commit |
| any held | valid CUSTODY_ACCEPTED、known attempt/binding | AWAITING_RECEIPT | remote durable custodyをFULL commitしcurrent attempt timeout/retry candidateをclear。Payloadとrequired application Receipt待ちは維持 |
| AWAITING_RECEIPT | current ATTEMPT_RECEIPT_TIMEOUT、accepted / custody / lost-unknown / corrupt-or-invalid possible-delivery send、attempts_in_cycle < 8 | RETRY_WAIT | EFFECT_POSSIBLEを保持。Event dedup bindingでsafe retry |
| AWAITING_RECEIPT | current 8th ATTEMPT_RECEIPT_TIMEOUT、required未到達 | PARKED_RETRY | public reason=NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、event_park_cause=NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT、payload保持 |
| any held / PARKED_RETRY | matrix上operator actionが必要なDisposition | PARKED_RETRY | public reason=NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、corresponding event_park_causeを保存 |
| any held / PARKED_RETRY | VALID_RECEIPT required stage到達 | SATISFIED + RELEASED | Receipt / Outcome / payload releaseをFULL commit |
| any | stale old-attempt ATTEMPT_RECEIPT_TIMEOUT | current不変 | bounded stale observationだけ |
| eligible PARKED_RETRY | namespace latest availability available=1、epoch > last seen/consumed、resumable park cause | HELD_READY | owner別AVAILABILITY_CONSUMEでsummary / cycle / seen+consumed epoch / revision / cursorをatomic commit。Active Event一括更新0 |
| any EventFact | EVENT_RESUME_REQUEST、ledger same op/digest hit | currentまたはpersisted-result state | state/revisionを再評価せずALREADY_RESUMED等のcached result |
| any EventFact | resume/discard operation IDが既存だがdigestまたはkind不一致 | current | exact RESUME_CONFLICT / DISCARD_CONFLICT、state/revision評価0 |
| PARKED_RETRY | EVENT_RESUME_REQUEST、unseen operation、expected revision一致、ledger used < 8、cause guard成功 | HELD_READY | new cycle / ledger replay result / revisionをatomic commit |
| PARKED_RETRY | EVENT_RESUME_REQUEST、unseen 9th distinct operation | PARKED_RETRY | LIMIT_EXHAUSTED / CAPACITY_EXHAUSTED、revision不変 |
| any EventFact | EVENT_DISCARD_REQUEST、ledger same op/digest hit | current | current state/revisionを再評価せずcached discard result |
| any held / PARKED_RETRY | EVENT_DISCARD_REQUEST、unseen operation、state/revision/guard成功 | DISCARD_COMMITTING | atomic discard transactionをstage。外部success / payload eraseはcommit前0 |
| DISCARD_COMMITTING | atomic discard commit成功 | FAILED_DEFINITIVE + DISCARDED | audit / tombstone / payload release / cached replay resultを公開 |
| DISCARD_COMMITTING | commit failure / uncertain | durable stateは旧held stateまたはDISCARDEDの一方 | failureではpayload保持、unknownではrecoveryでauthoritative stateを決定 |
| PARKED_RETRY | restart、cancel、stale epoch | PARKED_RETRY | new cycle / payload release 0 |
| RELEASED | duplicate input | RELEASED | bounded duplicate observation / cached resultだけ |
| DISCARDED | duplicate discard same operation/digest | DISCARDED | cached ALREADY_DISCARDED result、payload二重解放0 |

Foundation M1aのdefault custody policyは`NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE`です。`TRANSPORT_CUSTODY_ACCEPTED`だけではEventFact payloadを解放しません。

Receiverはvalid APPLICATIONのpayload/bindingとDelivery recordをFULL ingress commitした同じtransactionでcached `CUSTODY_ACCEPTED` replyをPENDINGにできます。Commit前、invalid/duplicate-with-conflict、capacity/copy failureでは生成しません。Replyはtriggering attempt IDをechoしapplication evidenceを含みません。Senderのvalid custody inputはknown current/old attemptへ収束し、remote durable custody flagを一度だけcommitします。Exact duplicateはstate/spool revisionを変えません。Supported custody policyは`UNTIL_REQUIRED_EVIDENCE`だけなので、Command/Eventともlocal payload、terminal Outcome、required Receiptをcustodyだけで解放/満足させません。ただし同じApplicationをtransport retryする必要はなく、current attempt timeout/internal retryをclearしてapplication Receiptを待ちます。Cached reply send/retryは12章reverse-send state machineに従います。

### Parkと再開

- PARKED_RETRYはfailureでもsuccessでもなく、NinlilがEventFactを保持しているactive stateです。
- PARKED_RETRYへ入るcommitはpublic reason=NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、internal event_park_cause、retry_cycle_id、attempts_in_cycle、last attempt、delivery_possibleを含みます。
- timer経過やrestartだけで新cycleを開始しません。
- fresh Bearer availability epochかつavailable=1、またはoperator resumeのatomic commitだけがnew retry_cycle_idを作れます。
- new cycleの最初のattemptも新attempt IDを使います。
- park中にrequired Receiptが到着した場合、resumeを待たずSATISFIED + RELEASEDへ進みます。
- explicit discardだけがrequired Receiptなしにpayloadを解放できます。その場合はFAILED_DEFINITIVEです。

## Late evidence

terminal Outcome後のvalid Receiptは次のatomic updateだけを許します。

- latest_evidence_stageを単調に進める。
- late evidence recordを追加する。
- evidence observed timeとissuer timeを保存する。
- DesiredStateCommandのterminal Outcomeは不変。
- DISCARDED EventFactのterminal Outcomeとtombstoneは不変。payloadを復元しない。

次は禁止します。

- terminal OutcomeをSATISFIEDへ変更する。
- deadline_verdictをMISSED / INDETERMINATEからMETへ変更する。
- 元transactionのterminal reasonを消す。
- late Receiptを期限内SLOの成功数へ加える。

Snapshotは最低限、terminal Outcome、deadline_verdict、latest_evidence_stage、late_evidence_presentを別fieldで返します。EventFactのdeadline_verdictはNOT_APPLICABLEです。PARKED_RETRY中のReceiptはlate evidenceではなく、通常のpositive evidenceです。

## 競合matrix

同じlogical_timeではpriority表を適用します。異なるlogical_timeでは先にdurable commitしたstateを次inputのprevious stateにします。

| Input A | Input B | 規範結果 |
| --- | --- | --- |
| valid required Receipt | durable REMOTE_CANCEL_RESULT / LOCAL_CANCEL_REQUEST | Receiptを先にcommit。SATISFIEDならcancelはALREADY_TERMINAL / TOO_LATE、Outcome反転0 |
| valid Receipt | valid Disposition | Receiptを先にcommit。Dispositionはpositive evidenceを取り消さない |
| valid Receipt | retry exhaustion / timeout | Receiptを先にcommit。新retryやparkを作らない |
| valid Receipt | Command deadline | Receiptを先に評価し、期限境界規則を適用 |
| LOCAL_CANCEL_REQUEST | Command deadline | どちらもdurable inputならcancelを先に評価。pre-send / no-effectならCANCELLED_BEFORE_EFFECT |
| valid Disposition | retry exhaustion | exact matrixのcertainty/guidance/reasonを保持し、二重terminal transitionを作らない |
| storage commit failure | success / Receipt / side effect | failureを先に処理し、commit依存のsuccessとside effectを発生させない |
| delivery_complete | DEFER token timeout | completionを先にcommit。成功ならtimeoutはexpired token no-op |
| delivery_complete commit failure | DEFER token timeout | completion successを出さず、timeoutでtoken expiry + RECOVERY_REQUIRED |
| DEFER token timeout | process crash | recovery後にactive tokenまたはexpired token + RECOVERY_REQUIREDの一方へ収束 |
| EventFact required Receipt | discard | Receiptを先にcommitしSATISFIED + RELEASED。discardはNINLIL_EVENT_DISCARD_ALREADY_RELEASED |
| EventFact discard | resume / Bearer availability epoch / dispatch | discardを先にcommit。new cycle / attemptを作らない |
| EventFact discard | timeout / retry exhaustion | discardを先にcommit。PARKED_RETRYを作らない |
| EventFact discard | cancel | durable ingress sequence順。最終stateはDISCARDEDで、cancelはspoolを解放しない |
| EventFact discard | discard storage failure | payloadを保持し、DISCARDEDを返さない |
| 8th attempt timeout | fresh Bearer availability epoch + `available=1` | timeoutでPARKED_RETRY / NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENTをcommit後、fresh epoch guardが成立すれば同時刻にnew cycleをcommit可能 |
| PARKED_RETRY required Receipt | operator resume | Receiptを先にcommitしSATISFIED + RELEASED。resumeはNINLIL_EVENT_RESUME_ALREADY_RELEASED |
| PARKED_RETRY required Receipt | fresh Bearer availability epoch + `available=1` | Receiptを先にcommitしSATISFIED + RELEASED。epochはlast-seenだけ更新可能でnew cycle 0 |

## ALL_TARGETS aggregation for M1b

本節はM1b以降のnormative forward contractです。M1aの実装必須ではありません。M1aはtarget_count=1を強制します。

### Supersede forward rule

- M1bでdescriptorが許可したreplace scopeに限りSUPERSEDE_SELECTEDを導入できます。
- attempt未作成のtargetだけをSUPERSEDED_BEFORE_DISPATCH、reason NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATIONへ進められます。
- attempt作成後はold transactionを自動成功・取消・supersedeにせず、new generationを別transactionとして扱います。
- M1a decoder / reducerがSUPERSEDE_SELECTEDを受理または生成してはなりません。

### Aggregate progress

Group transactionはOutcomeと別に次のcountを返します。

- total_targets
- satisfied_targets
- active_targets
- expired_targets
- cancelled_targets
- superseded_targets
- definitive_failed_targets
- unknown_targets
- late_evidence_targets

一部成功をSATISFIEDと表示してはなりません。

### ALL_TARGETS terminal rule

1. 全targetがSATISFIEDならtransactionはSATISFIED。
2. 1件でもactiveならtransactionはterminalにしない。ただし全体deadline/evidence close規則を適用する。
3. 全targetがterminalで1件でもOUTCOME_UNKNOWNならtransactionはOUTCOME_UNKNOWN。
4. unknownがなく1件でもFAILED_DEFINITIVEならtransactionはFAILED_DEFINITIVE。
5. unknown/definitive failureがなく1件でもEXPIREDならtransactionはEXPIRED。
6. 全targetがCANCELLED_BEFORE_EFFECTならtransactionはCANCELLED_BEFORE_EFFECT。
7. 全targetがSUPERSEDED_BEFORE_DISPATCHならtransactionはSUPERSEDED_BEFORE_DISPATCH。
8. SATISFIEDとcancel/supersede等が混在しALL_TARGETSを満たさない場合、transactionはFAILED_DEFINITIVE、reasonはNINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT。

Late evidenceでこのaggregate terminal Outcomeを反転しません。target別latest evidenceとaggregate countだけを更新します。

## Runtime step / capacity observability boundary

State reducerがcapacityをreserve / consume / releaseする意味の正本は[12-foundation-abi.md](12-foundation-abi.md)「11.1 Capacity accounting」の11-kind tableです。本章のstateとの対応は次を必須とします。

- Capacity snapshotはSERVICE〜DEFERRED_TOKENをkind順でexactly 11件返し、roleで未使用のkindも0値entryを省略しません。
- `used`はcommit済み/live unit、`reserved`はCoreが所有する未使用reservation recordです。常にchecked `used + reserved <= limit`、`high_water = max(previous, used + reserved)`です。予約なし消費、underflow、limit超過はstorage corruptionとしてfail closedします。
- 複数kindを必要とするadmission / callback / retryはkind昇順で全てreserveし、途中失敗は逆順releaseしてから戻ります。全reservationが揃う前にeffect / callbackを開始しません。
- Resource-kind `capacity_epoch`は新namespaceで1。そのkind不足でworkを実際にblock/rejectした後、同classのworkを再評価可能にするrelease / recovery FULL commitでだけstrict incrementします。Poll、reservation、使用増、無関係release、restartで増やしません。Bearer availability_epochや別resource kindと比較しません。
- Tableのunit / limit / used / reserved / release eventを本章stateの別名で再定義しません。とくにEvent resume ledgerはEVENT_SPOOL_BYTES、cancel recordはTRANSACTION、token tombstoneはRESULT_CACHE、active tokenはDEFERRED_TOKENの規則に従います。
- `EVENT_SPOOL_BYTES`はlive中checked `used + reserved = payload.length + 2560`です。Successful management operationは対応slotだけをreserved→usedへ移し、terminal retained usedは`successful_resume_operation_count * 256 + (discard_operation_committed ? 512 : 0)`、reservedは0です。Attempt / summary等のphysical overheadをこのportable kindへ加えません。

### Step counterとbudget preflight

[12-foundation-abi.md](12-foundation-abi.md)「11.2 Step budget accounting」がcounter unitとincrement pointの唯一の正本です。`ninlil_runtime_step()`はcall開始時にresult counterを0とし、step外のpublic API workを数えません。

| Counter | Exact unit / increment point |
| --- | --- |
| ingress_processed | non-EMPTY `receive_next` messageをCoreがconsumeし`release_received`した直後に1。Valid / duplicate / invalid / copy-capacity failureを含み、EMPTY / Port errorは0 |
| callbacks_invoked | `on_delivery`または`on_reconcile`へactual function entryする直前に1。Callback前commit failureは0 |
| state_transitions | runtime_stepが開始した1つのStorage FULL transactionでCore-owned durable bytes/stateが変化し、commit OK観測直後に1。Multi-record atomic groupも1、read/no-op/rollback/failure/COMMIT_UNKNOWNは0 |
| bearer_sends | Bearer `send` actual invocationのPort return直後に1。Return kindを問わず1、TxGate denial/send前failureは0 |
| transactions_terminalized | authoritative transactionがnon-terminal→terminalへ初めて変化したFULL commit OK後に1。Replay/readは0 |
| events_parked | EventFactがnon-PARKED→PARKED_RETRYへ初めて変化したFULL commit OK後に1。Replay/既存PARKEDは0 |

`transactions_terminalized`と`events_parked`はbudget categoryではなくstate transition分類です。同じFULL commitで`state_transitions`と該当分類counterを各1にできますが、同じtransitionを重複加算しません。COMMIT_UNKNOWNは当該stepでは0、later recovery readで過去counterを再構成しません。

External side effect前は次のworst-case budgetをatomicにpreflightします。Reservation自体はcounterを増やさず、実際に不要となった分は同じstepへ返します。

| Scheduler micro-operation | Required remaining budget before start | Boundary |
| --- | --- | --- |
| receive one ingress | ingress 1 + state transition 1 | durable ingressを保証できるheadroomなしに`receive_next`を呼ばない。EMPTY/commit不要dropではstate reservationを返す |
| timer/reducer/recovery/cleanup durable mutation | state transition 1 | 1 FULL groupをpartial stagingしない |
| on_delivery dispatch | callback 1 + state transitions 2 | callback前DELIVERY_STARTEDとreturn後COMPLETE/FATAL/contract result。DEFERは2つ目を返し、volatile resultを次stepへ持ち越さない |
| on_reconcile dispatch | callback 1 + state transition 1 | known/result/recovery actionの最大1 FULL groupを同じstepで完了。Commit不要actionは返す |
| ordinary Bearer send | bearer send 1 + state transition 1 | send outcomeのdurable observation headroomなしにPortを呼ばない |
| remote cancel request send | bearer send 1 + state transitions 2 | pre-send gate closeとpost-return observation / definite-WOULD_BLOCK reopenを両方preflight |

1 logical operationが複数rowを不可分に必要とする場合はcategoryごとにchecked sumを予約します。Attempt prepare→later sendやresult commit→later reply sendのようにdurable boundaryで分割可能なworkは別micro-operationです。どれか不足ならPort / callback / storage side effect 0でqueueに残し`more_work=1`です。Budget 0はそのcategoryのwork 0を意味し、pending workがあればcounter 0 / `more_work=1`です。Config上限超過はNINLIL_E_INVALID_ARGUMENTでsilent clampしません。

`ninlil_runtime_step()`はcurrent logical timeで直ちに処理可能なworkが残る場合`more_work=1`とします。`has_next_wake=1`は、durable pending timerのうちcurrent trusted clock epochと一致する最早のfuture pointだけを`next_wake_clock_epoch_id / next_wake_at_ms`に返します。Due-now timerはnext wakeではなくmore_workです。`has_next_wake=0`ではepoch/timeともzero、1ではepoch non-zeroかつ`next_wake_at_ms > current now_ms`です。Clock uncertain / epoch mismatch / port failureではwakeを推測せず0にし、NINLIL_REASON_CLOCK_UNCERTAIN causeをaddします。Public `degraded_reason`は他のactive causeを含む固定priorityから導出するため、常にCLOCK_UNCERTAINとは限りません。PARKED_RETRYだけでtimer wakeを生成しません。

複数ready ownerの選択、durable scheduler cursor、work class/stable key、step-entry/fresh Clock call、Bearer state poll、first-error stopは12章11.0だけを正本とします。本章のsame-time priorityは選ばれた同一transaction/target内の競合を畳む規則であり、ready owner間fairnessやPort call順を上書きしません。

### Metricsとhealth

[12-foundation-abi.md](12-foundation-abi.md)「11.3 Metrics and health」がmetrics increment/reset/saturationとhealth cause lifecycleの正本です。State reducerとの対応は次です。

| Metric | Exact state/observation boundary |
| --- | --- |
| submission_calls | Valid service handle、outer submission/result ABI、owner/re-entry validation通過後のsubmit invocationごとに1。以後のnested/content/provider/Storage errorを含み、outer validation failureは0 |
| admitted_ready / already_admitted / rejected / idempotency_conflicts | Public returnがNINLIL_OK + 対応exact kindのとき各1。API error / COMMIT_UNKNOWNはkind counter 0 |
| transactions_satisfied / transactions_expired / transactions_failed_definitive / transactions_outcome_unknown | このmetrics epochでnon-terminalから対応Outcomeへ初めて変わるFULL commit OKごとに1。CANCELLED_BEFORE_EFFECT、existing terminal load/replayは対象外 |
| events_parked | non-PARKED→PARKED_RETRY FULL commit OKごとに1 |
| events_resumed | PARKED→READYのavailability resumeまたは初回explicit RESUMED commitごとに1。Replay 0 |
| events_discarded | 初回DISCARDED audit/tombstone FULL commit OKごとに1。Replay 0 |
| late_evidence | terminal後のnew valid late evidence materialをraw insertまたはsummary updateへdurably commitするごとに1。Exact duplicate 0 |
| duplicate_logical_delivery | valid duplicate APPLICATIONをdurable identity/bindingで認識しnew callbackを抑止したmessageごとに1 |
| application_callback_invocations | on_delivery actual function entry直前に1 |
| reconcile_invocations | on_reconcile actual function entry直前に1 |
| delivery_token_timeouts | active token→expired/RECOVERY_REQUIRED FULL commit OKごとに1。Late replay 0 |
| storage_failures | Published RuntimeのStorage PortがBUSY、NO_SPACE、IO_ERROR、CORRUPT、COMMIT_UNKNOWN、UNSUPPORTED_SCHEMA、またはcontext上unexpectedなNOT_FOUND/BUFFER_TOO_SMALLを返すごとに1。Expected miss/end/size probe、create前/destroy後は0 |
| bearer_would_block | Published Runtimeのactual Bearer send invocationがWOULD_BLOCKを返すごとに1。同じcancel attemptの各retryも数える |

- Per-delivery `delivery_count`、token generation、`prior_callback_invocations`はchecked uint64で、narrowingしません。`application_callback_invocations`と`reconcile_invocations`は別のuint64 metricsでactual function entry直前に各1増やします。Per-step `callbacks_invoked`は両callbackを合算するbounded ABI counterで、durable countやmetricsの代用ではありません。
- Admission result kind metricsはNINLIL_OKのexact kindだけ、terminal / park / resume / discard / token-timeout metricsは対応する初回FULL commit OKだけで1増えます。Replay、read、duplicate、rollback、definite failure、COMMIT_UNKNOWNでは増やしません。
- `late_evidence`はterminal後のnew valid late evidence insert、`duplicate_logical_delivery`はvalid duplicate APPLICATIONを認識してcallbackを抑止したmessage、`bearer_would_block`はactual sendがWOULD_BLOCKを返した各回を数えます。
- 全metrics counterは該当observation / commit OK直後にchecked incrementしUINT64_MAXでsaturateします。Saturationはreducer / healthを変更せず、metrics snapshot自身はcounterを増やしません。

Runtime healthはactive degraded-cause multisetから導出します。Cause 0件だけがNINLIL_HEALTH_OK / NINLIL_REASON_NONE、1件以上はNINLIL_HEALTH_DEGRADEDで、次の固定priorityの最上位reasonを返します。NINLIL_HEALTH_FATALはM1a generated 0です。

| Priority | Active cause / degraded reason | Add / clear boundary |
| ---: | --- | --- |
| 1 | Storage corrupt / definite I/O / NINLIL_REASON_STORAGE_IO | failureでadd。successful reopen + schema/capacity/recovery scan完了で同causeをclear |
| 2 | unresolved commit unknown / NINLIL_REASON_STORAGE_COMMIT_UNKNOWN | unknown観測でadd。authoritative record resolutionでclear |
| 3 | callback/known-result contract fence / NINLIL_REASON_CALLBACK_CONTRACT | recovery marker commitでadd。該当deliveryのvalid reconcile terminal commitでclear |
| 4 | callback FATAL/application failure fence、Bearer receive/state denial / NINLIL_REASON_APPLICATION_FAILED | Durable markerまたは12章instance source keyのexact add/clear |
| 5 | origin provider permanent failure/invalid decision / NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE | NINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALIDでadd。後続valid provider evaluationでclear。Temporary failureはadd 0 |
| 6 | clock permanent/uncertain/epoch fence / NINLIL_REASON_CLOCK_UNCERTAIN | unsafe observationでadd。trusted non-regressing sampleとaffected guard再評価後clear |
| 7 | non-recoverable counter headroom / NINLIL_REASON_COUNTER_EXHAUSTED | exhaustion commit/observationでadd。同Runtime instanceではclearしない |
| 8 | entropy exhaustion、Bearer/TxGate method fault、internal invariant fence / NINLIL_REASON_OUTCOME_UNKNOWN | 12章distinct source-key tableのexact add/clear。Internal invariantは同Runtime instanceでclearしない |

Source key、durability、idempotent add、method-specific clearは12章11.3だけを正本とします。同じkeyの反復観測をreference-countせず、別source/markerは最後の解消まで保持します。Current degraded reasonは発生順やhash iterationではなく表のpriorityだけで決めます。通常のAPI invalid/rejection、Bearer WOULD_BLOCK、provider temporary failure、business transactionのOUTCOME_UNKNOWNだけではhealth causeを追加しません。

## Storage error

### Admission中

- commit前のdefinite failureではtransactionを作らず、ADMITTEDを返しません。
- commit acknowledgement不明ではCOMMIT_UNKNOWNとし、REJECTEDを返しません。
- callerの同じidempotency keyによる再提出で、existing commitまたはnew admissionの一方へ収束します。

### Attempt preparation中

- attempt commit失敗時はbearer sendを行いません。
- attempt commit acknowledgement不明時はsendを行わずnamespaceをfenceします。Recoveryでnon-commit確定ならattempt/budget/indexは全て不在としてpreparationをやり直し、commit確定ならdurable ATTEMPT_PREPAREDを同じattempt IDでsendします。
- Durable send observation前のrecovery/reinvokeはsame attempt、observation後のlogical retryだけがsame transaction + new attempt IDです。

### Receipt処理中

- Receipt commit前にtargetをSATISFIEDとして公開しません。
- commit失敗時はdurable ingress copyを保持します。
- commit結果不明時はrecoveryでhighest stageを読み直します。

### Application result中

- effect前のDELIVERY_STARTED commit失敗ではcallbackを呼びません。
- callback effect後、result cache commit前のfailureではAPPLIEDを発行しません。
- recoveryでeffectを証明できなければRECOVERY_REQUIRED / EFFECT_POSSIBLEです。
- callback前token/expiry commit失敗ではcallbackを呼ばず、applicationにasync effect開始機会を与えません。
- DEFER return後に追加token commitを要求しません。既存DELIVERY_STARTED recordがrecoveryの正本です。

### EventFact discard中

- discard audit、terminal Outcome、DISCARDED tombstone、payload解放は1つのstorage transactionです。
- commit前またはdefinite rollbackでは元のheld / PARKED_RETRY stateとpayloadを維持します。
- commit acknowledgement不明ではDISCARDEDを返しません。recoveryでaudit+tombstoneの有無を読みます。
- recovery後は「payloadあり、discard auditなし」または「payload解放済み、discard audit+tombstoneあり」のどちらかだけを許します。
- payload解放済み、discard auditなしはstorage corruptionとしてfail closedにし、discard成功と表示してはなりません。
- discard commit後にin-flight Receiptが来てもtombstoneを削除せず、late evidenceとして追記します。

### Storage full

- 新規SubmissionをNINLIL_REASON_CAPACITY_EXHAUSTEDで拒否できます。
- admitted transaction、unacknowledged EventFact、required evidence、active idempotency mappingを削除して空きを作ってはなりません。
- storage pressureをsuccess、queued、sent、received、appliedとして表示してはなりません。

## Restart and crash recovery

Runtime起動時は、external inputやtimerを処理する前にRECOVERY_FENCEを適用します。

### Named crash registry

Named crash hookのexact nameとplacementは[12-foundation-abi.md](12-foundation-abi.md)「17. Named fault hook registry」が唯一の正本で、[08-foundation-release.md](08-foundation-release.md)「Named crash boundaries」はそこへのrelease-gate referenceです。本章が別名hookを作ったり、iterator operationをstate transition hookとして追加してはなりません。

Mandatory vectorは、少なくともadmission reference / transaction / roster / reservation / idempotency / outbox / spool / sequence commit、Applicationおよびcancel ATTEMPT_PREPARE、Bearer send後、Endpoint event admission、DELIVERY_STARTED、application effect後、token invalidation、result cache、Receipt commit/send、cancel tombstone/result、resume ledger、discard audit/tombstone/payload release、terminalizationの全FULL boundaryをregistry上のnamed hookへ対応させます。対応するauthoritative hookがないstate boundaryが1つでもあれば、実装で独自hook名を追加せず08 / 12を先に更新するまでM1a completion gateはblockedです。

### 共通手順

1. storage schemaとmigration markerを検査する。
2. backend規則に従いincomplete storage transactionをrollbackまたはcommittedとして確定する。
3. namespace transaction sequence counterと全transactionのnon-zero / unique / upper-bound整合を検査する。partial sequence allocation、duplicate sequence、counterより大きいtransaction sequenceはstorage degradedとし、推測で再番号付与しない。
4. durable service registryとSERVICE accountingを列挙する。Volatile Service handle/callback attachmentは0件で開始する。
5. admitted non-terminal transaction、target、reservation、service quota bucketを列挙する。
6. durable ingress、prepared attempt、Delivery state、EventFact spool、INGRESS accountingを列挙する。
7. terminal Outcomeをdispatch対象へ戻さない。
8. Command timer / retry budgetとEventFact retry cycle / Bearer availability epochを再計算する。Runtime capacity epochと混同しない。
9. recovery commit後、かつrecordのexact service revisionがcurrent Runtimeへattach済みの場合だけ、そのserviceのexternal effectを再開する。

Recreate直後はpersist済みservice registry slotをSERVICE `used`として復元しますが、旧processのfunction/user pointerやService handleを復元しません。Exact service attach前のpending origin dispatch、callback、reconcile、cached reverse sendはrunnableでなく、step counter/send/callback 0です。Valid inboundはpersist済みdescriptorでINGRESS/INBOX_COMMITTEDまでdurable化できますがpositive reply/effect 0です。Exact attachはold pending recordのdescriptor revisionへだけwakeを発行し、new revision callbackへのfallback、latest-revision自動変換、pointer値の跨process比較を行いません。

### Attempt

- ATTEMPT_PREPAREDにdurable send observationがなければ、same-attempt send micro-operationが未完了です。Fresh clock/TxGate permitで同じimmutable messageとattempt IDを再invokeでき、new entropy/attempt budgetは消費しません。Observation COMMIT_UNKNOWN中は再sendせず、authoritative non-commit確定後だけsame attemptを再invokeします。
- Durable send observation後のlogical retryだけが同じtransaction ID + new attempt IDを使います。Receiver dedupによりsend後/observation前crashのsame-attempt duplicateでcallback/effectを増やしません。
- Application nonce/wire暗号はM1a simulator範囲外で、Core attempt ID再利用規則を「nonce再利用禁止」と混同しません。後続wire profileはsame logical attempt retransmission用nonce/sequence契約を別に定義します。
- attempts_usedをrollbackしません。

### DesiredStateCommand recovery

- 未dispatchを証明でき、deadline経過済みならEXPIREDです。
- delivery/effect可能性がありevidence close経過済みならOUTCOME_UNKNOWNです。
- DELIVERY_STARTEDだけが残るEndpointは、callback中crash、DEFER中crash、sync result commit前crashを区別できないため、durable tokenをexpiredへcommitしてRECOVERY_REQUIREDへ進み、apply contractに従いon_reconcileを呼びます。
- process restart前のtokenをactiveへ戻さず、bounded expired-token retentionへ移します。
- result cacheがあればcached Receiptを再発行できます。

### EventFact recovery

- HELD_READY、AWAITING_RECEIPT、RETRY_WAIT、PARKED_RETRYを保持します。
- admission済みgrant snapshotを保持し、grant expiryだけでeventを削除、terminal化、cycle取消ししません。
- caller idempotency mapping、event ID mapping、transactionの一部だけが存在する場合は新規admissionを行わずstorage degradedにします。
- attempts_in_cycle、retry_cycle_id、cumulative_attemptsをrollbackしません。
- PARKED_RETRYはrestartだけでHELD_READYへ戻しません。
- recovery後、persist済みnamespace latest Bearer stateがfresh `available=1`でEventのseen/consumedよりstrictly greaterなら、ordered ingressを探さず`AVAILABILITY_CONSUME` candidateを再構成し、park-cause guardを満たすEventごとに最大1回new cycleへ進めます。
- resume operation IDがcommit済みなら同じoperationでcycleを再度resetしません。
- required Receiptのcommit済みrecordがあればSATISFIED + RELEASEDへ収束できます。
- discard audit+tombstoneがcommit済みならFAILED_DEFINITIVE + DISCARDEDへ収束し、payloadを再構成しません。
- DISCARD_COMMITTINGはdurable stateではありません。backendにprepared transactionが残る場合、state load前に旧stateまたはDISCARDEDの一方へ回復します。

### Clock uncertainty

restart後にelapsed timeを証明できない場合:

- 旧epochのnow / deadline / retry / expiry値をnew epochと数値比較しません。Commandのdeadline_verdictはNINLIL_DEADLINE_INDETERMINATEです。
- 未dispatchとno-effectを証明できるCommandはEXPIRED、reasonはNINLIL_REASON_CLOCK_UNCERTAINです。
- effect可能なCommandはOUTCOME_UNKNOWN、reasonはNINLIL_REASON_CLOCK_UNCERTAINです。
- EventFactのdeadline_verdictはNOT_APPLICABLEで、clock uncertaintyだけではstateを変えません。
- EventFactがRETRY_WAITでtrusted new local clock epochを得られるなら、旧absolute timerを引き継がずprofile backoffだけからnew internal not-beforeを作り直します。trusted sampleなしではdispatchしません。PARKED_RETRYならfresh Bearer availability epoch + `available=1`またはoperator resumeを待ちます。

## Reason code

[12-foundation-abi.md](12-foundation-abi.md)のpublic reason integer registryだけが正本です。本章は別名、略称、新しいinteger reasonを定義しません。

### M1a public-generated admission / runtime reason

- NINLIL_REASON_NONE
- NINLIL_REASON_UNSUPPORTED_DIRECTION
- NINLIL_REASON_TARGET_COUNT_UNSUPPORTED
- NINLIL_REASON_INVALID_SCHEMA
- NINLIL_REASON_INVALID_PAYLOAD_LENGTH
- NINLIL_REASON_DEADLINE_INVALID
- NINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED
- NINLIL_REASON_EVIDENCE_UNSUPPORTED
- NINLIL_REASON_CAPACITY_EXHAUSTED
- NINLIL_REASON_IDEMPOTENCY_CONFLICT
- NINLIL_REASON_GRANT_INVALID
- NINLIL_REASON_GRANT_EXPIRED
- NINLIL_REASON_GRANT_LIMIT_EXCEEDED
- NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE
- NINLIL_REASON_STORAGE_IO
- NINLIL_REASON_STORAGE_COMMIT_UNKNOWN
- NINLIL_REASON_CLOCK_UNCERTAIN
- NINLIL_REASON_RATE_EXHAUSTED
- NINLIL_REASON_TARGET_UNAUTHORIZED
- NINLIL_REASON_CALLBACK_CONTRACT

NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLEはこの一覧中で唯一Submission / transaction / management result reasonには生成せず、provider permanent/invalid responseからRuntime step health `degraded_reason`へだけ生成します。Default guidance metadataはNINLIL_RETRY_OPERATOR_ACTIONです。

### M1a public-generated outcome / operation reason

- NINLIL_REASON_REQUIRED_EVIDENCE_MET
- NINLIL_REASON_REQUIRED_EVIDENCE_LATE
- NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH
- NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_PENDING
- NINLIL_REASON_EFFECT_POSSIBLE_EVIDENCE_MISSING
- NINLIL_REASON_RETRY_BUDGET_EXHAUSTED_NO_EFFECT
- NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED
- NINLIL_REASON_COUNTER_EXHAUSTED
- NINLIL_REASON_STALE_AVAILABILITY_EPOCH
- NINLIL_REASON_RESUME_CONFLICT
- NINLIL_REASON_STALE_SPOOL_REVISION
- NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT
- NINLIL_REASON_DISCARD_CONFLICT
- NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH
- NINLIL_REASON_CANCEL_AFTER_EFFECT_POSSIBLE
- NINLIL_REASON_EVENT_FACT_IMMUTABLE
- NINLIL_REASON_TRANSPORT_RETRY
- NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE
- NINLIL_REASON_APPLICATION_FAILED
- NINLIL_REASON_OUTCOME_UNKNOWN
- NINLIL_REASON_RECEIVER_UNAVAILABLE
- NINLIL_REASON_APPLICATION_COMPLETION_TIMEOUT
- NINLIL_REASON_RECONCILE_RETRY_LATER

### M1a public reason generated-zero exact set

- NINLIL_REASON_UNSUPPORTED_FAMILY
- NINLIL_REASON_UNSUPPORTED_SELECTOR
- NINLIL_REASON_INVALID_CONTENT_DIGEST
- NINLIL_REASON_ATTEMPT_RECEIPT_TIMEOUT_INVALID
- NINLIL_REASON_MODIFICATION_REQUIRED
- NINLIL_REASON_EVENT_RECEIPT_TIMEOUT
- NINLIL_REASON_CYCLE_EXHAUSTED_TRANSIENT
- NINLIL_REASON_BEARER_UNAVAILABLE
- NINLIL_REASON_CAPACITY_UNAVAILABLE

上記9 symbolだけが12章 / YAMLの`m1a_public_generated_zero` exact setです。Submission result、transaction / target snapshot、step health reason、management resultへ生成しません。Familyとattempt timeoutはservice registration API status、selectorはABIで表現不能、content digest mismatchはNINLIL_E_INVALID_ARGUMENT、modification-required guardはM1aに存在しません。Event timeout / parkの詳細はattempt observationと`ninlil_event_park_cause_t`だけへ保持し、public PARKED reasonはreachableなEVENT_RETRY_CYCLE_PARKEDに固定します。

ADMITTED_SCHEDULED、COUNTER_OFFEREDとcaller schedule / selector fieldもM1a generated 0ですが、public reasonの9-symbol setには含めません。ABI 0.1 known Submissionで表現できず、future tailはignoreします。

### M1b forward-only reason

- NINLIL_REASON_M1B_SUPERSEDED_BY_NEW_GENERATION
- NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT

M1b reasonをM1a reducer、M1a fixture、M1a public resultで生成してはなりません。NINLIL_E_STORAGE_COMMIT_UNKNOWN、NINLIL_E_INVALID_STATE、NINLIL_E_CONFLICT、NINLIL_E_DEGRADEDはAPI statusであり、reasonと混同しません。

reason textはCoreに保存しません。product adapterが12章のstable reason codeをoperator表示とrunbookへ写像します。

## Mandatory test vectors

各vectorはinitial snapshot、ordered inputs、expected durable writes、expected next state、public result、reason、post-commit effectsをfixture化します。

### Admission

- M1A-ADM-001: valid single-target Commandはlocal assuranceだけtrueでADMITTED_READY。
- M1A-ADM-002: target_count=2はNINLIL_REASON_TARGET_COUNT_UNSUPPORTEDでREJECTED、record 0。
- M1A-ADM-003: DesiredStateのsame key / same digestは同じtransaction IDでALREADY_ADMITTED。
- M1A-ADM-004: same key / different digestはIDEMPOTENCY_CONFLICT / NINLIL_REASON_IDEMPOTENCY_CONFLICT。
- M1A-ADM-005: reservation不足はNINLIL_REASON_CAPACITY_EXHAUSTED、payload ownershipはcaller。
- M1A-ADM-006: admission各write point crashは全recordなし、または全recordあり。
- M1A-ADM-007: commit acknowledgement不明後、同じkey再提出でtransactionが1件へ収束。
- M1A-ADM-008: assuranceのremote/route/window/bearer/airtime/compliance flagはすべてfalse。
- M1A-ADM-009: EventFact + NINLIL_NO_DEADLINE + grace 0はadmit可能。
- M1A-ADM-010: finite EventFact deadlineまたはnonzero graceはNINLIL_REASON_EVENTFACT_DEADLINE_UNSUPPORTED。
- M1A-ADM-012: commit acknowledgement不明のAPI statusはNINLIL_E_STORAGE_COMMIT_UNKNOWN。
- M1A-ADM-013: EventFact ALLOWはgrant ID/revision、request trusted clock epochと一致するevaluated/validity time、expiry/limits snapshotをadmissionと同じFULL commitへ含める。
- M1A-ADM-014: provider normal DENYはNINLIL_OK + REJECTED / NINLIL_REASON_GRANT_INVALID。
- M1A-ADM-015: expired grantはNINLIL_OK + REJECTED / NINLIL_REASON_GRANT_EXPIRED。
- M1A-ADM-016: grant binding mismatch / limit超過は各exact reasonでREJECTED。
- M1A-ADM-017: provider TEMP failureはNINLIL_E_WOULD_BLOCK + NINLIL_SUBMISSION_INVALID / reason NONE / zero assurance、transaction 0、health cause add/clear 0。
- M1A-ADM-018: provider PERMANENT failure / invalid decisionはNINLIL_E_DEGRADED + NINLIL_SUBMISSION_INVALID / reason NONE / zero assurance、transaction 0、NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE health causeをadd。後続valid evaluationでclear。
- M1A-ADM-019: admitted済みsame key/digestはgrant expiry後もALREADY_ADMITTED、spool/retry state不変。
- M1A-ADM-020: caller payload SHA-256 / content_digest mismatchはNINLIL_E_INVALID_ARGUMENT / reason NONE、transaction 0、ownership caller。NINLIL_REASON_INVALID_CONTENT_DIGEST生成0。
- M1A-ADM-021: same event ID / same canonical digest / same caller idempotency keyの3条件が揃う場合だけ、同じtransaction IDでALREADY_ADMITTED。
- M1A-ADM-022: same event ID / different canonical digestはIDEMPOTENCY_CONFLICT / NINLIL_REASON_IDEMPOTENCY_CONFLICT。
- M1A-ADM-023: EventFact admissionはcaller key mappingとevent ID mappingを同じFULL transactionへcommit。
- M1A-ADM-024: EventFact admission各write point crash後、両mapping+transactionが全てないか全てある。
- M1A-ADM-025: caller key mappingとevent ID mappingが別transactionを指すcorruption/conflictでは新規transaction 0。
- M1A-ADM-026: same event ID / same canonical digest / different caller keyはIDEMPOTENCY_CONFLICT。new key alias 0、既存mapping上書0。
- M1A-ADM-027: retry / new cycle / restart後もEventFactのevent IDとexact idempotency key bytesは不変、mapping countはboundedのまま。
- M1A-ADM-028: EventFact same caller key / same canonical digest / different event IDはIDEMPOTENCY_CONFLICT。event alias mapping 0、既存mapping上書0。
- M1A-ADM-029: empty namespaceの最初のadmissionはtransaction_sequence=1、次の新規admissionは2。state mutation / restart / terminal後も各sequence不変。
- M1A-ADM-030: same idempotent submissionのALREADY_ADMITTEDは既存transaction_sequenceを保ち、namespace sequence counter increment 0。
- M1A-ADM-031: namespace sequence counter=UINT64_MAXでは新規admissionをREJECTED / NINLIL_REASON_COUNTER_EXHAUSTED。new transaction / mapping / reservation 0、既存recordはbyte-for-byte不変。
- M1A-ADM-032: sequence counter increment、transaction_sequence、transaction / target / mapping / reservationの各write point crash後は全てrollbackまたは全てcommit。orphan sequence allocation 0。
- M1A-ADM-033: trusted pre-commit admission reference sampleのadmitted_at / epochとderived deadlineがadmission FULL commitに含まれ、commit後clock sampleで上書き0。
- M1A-ADM-034: pre-commit now=100、deadline=10、admission commit観測now=111でもADMITTED_READY + ownershipは成立。post-commit send 0でEXPIRED / NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCHを先にdurable commit。
- M1A-ADM-035: known ABI 0.1 Submissionはtarget_count=0または2以上だけをNINLIL_REASON_TARGET_COUNT_UNSUPPORTEDにする。Unknown future tailの変化からselector / scheduleを推測せず、UNSUPPORTED_SELECTOR / ADMITTED_SCHEDULED生成0。
- M1A-ADM-036: transaction ID drawは明示TRANSACTION_ID_DRAW_RESULTを最大4件reduceする。Zero/collision/partial/Port failureの後の4th validだけをadmission commitへ含め、4件全invalidならNINLIL_E_ENTROPY + SUBMISSION_INVALID、ownership/reservation/storage/sequence mutation 0、health DEGRADED。
- M1A-ADM-037: per-service origin quotaはinflight/window count/payload bytesをadmissionとatomic incrementし、terminalとatomic inflight decrementする。Inclusive boundary、exact delay、identity rotation/restart、ALREADY/conflict/COMMIT_UNKNOWNで二重加算/早期解放0。
- M1A-ADM-038: new admissionはmapping lookup→clock→transaction counter→scheduler owner counter→Event provider→quota/resource→entropy→FULL commit。Counter exhaustionはprovider/entropy/reservation0。
- M1A-ADM-039: Admission success/unknownはtransaction/owner両sequence、ID index、mapping/quota/reservation/root records all-or-none。ALREADY/conflictで両counter不変、orphan owner0。

### Deadline and ordering

- M1A-TIME-001: deadlineと同時刻のvalid required Receiptは先に処理されSATISFIED。
- M1A-TIME-002: deadlineと同時刻のDISPATCH_DUEはdispatchせずEXPIRED。
- M1A-TIME-003: cancelとvalid APPLIED Receiptが同時刻ならReceiptが勝ち、cancelはTOO_LATE。
- M1A-TIME-004: 任意のvalid Dispositionとvalid Receiptが同時刻ならReceiptを先に適用。
- M1A-TIME-005: Receipt evidence_timeがNINLIL_CLOCK_TRUSTED、deadline epochとexact match、now=deadlineならPROVEN_IN_TIME。
- M1A-TIME-006: Receipt evidence_timeがtrusted / same epochかつnow > deadlineならPROVEN_LATE、EXPIRED / NINLIL_REASON_REQUIRED_EVIDENCE_LATE。
- M1A-TIME-007: evidence_timeがNINLIL_CLOCK_UNCERTAINでController ingressもdeadline後ならTIME_UNKNOWN、grace closeでOUTCOME_UNKNOWN。
- M1A-TIME-008: evidence_grace_ms=0でもpositive evidence、deadline、closeの順。
- M1A-TIME-009: issuer evidence_timeのepochがdeadline epochと異なり、Controller durable ingressがdeadline後なら、issuer nowがdeadline前に見えてもTIME_UNKNOWN。
- M1A-TIME-010: issuer evidence_timeが比較不能でも、Controller durable ingressがtrusted / deadline epoch exact match / now <= deadlineなら保守的にPROVEN_IN_TIME。
- M1A-TIME-011: EventFactはevidence_timeをaudit保持するがdeadline verdict / timerを生成せず、deadline_clock_epoch_idはall-zero。
- M1A-TIME-012: DesiredState admissionはnon-zero deadline_clock_epoch_idとabsolute deadlineをatomic snapshotし、Bearer / Delivery / queryで不変に運ぶ。
- M1A-TIME-013: EndpointのCommand callback前clockがtrustedだがdeadline epoch不一致ならcallback 0、STALE_NOT_APPLIED、positive Receipt 0。
- M1A-TIME-014: same ownerでdeadline t=100、cancel t=101ならdeadlineが先、cancel t=100ならpriority 3でcancelが先。Work classがchronologyを追い越さない。
- M1A-TIME-015:異なるclock epoch candidateはepoch ID bytesを比較せずRecovery Fence + ordered input sequenceへ収束する。

### Cancel, disposition, retry

- M1A-CMD-001: Application Bearer send未呼出し / delivery_possible=falseのcancelはlocal fence FULL commitでCANCELLED_BEFORE_EFFECT、remote cancel send 0。
- M1A-CMD-002: delivery possible後cancelはnew Application attemptをfenceし、dedicated cancel attemptをcommitしてPENDING_REMOTE_FENCE。CANCEL_RESULT不足だけでterminal化しない。
- M1A-CMD-003: stale attempt Dispositionはcurrent attemptを変更しない。
- M1A-CMD-004: RETRY_LATERのrelative retry_delay_msをlocal now + max(profile backoff, delay)へ一度だけnormalizeし、internal not-before前にdispatchしない。
- M1A-CMD-005: derived internal retry_not_beforeがdeadline以上ならCommandを再dispatchしない。
- M1A-CMD-006: budget exhaustion + NO_EFFECT_PROVENはFAILED_DEFINITIVE。
- M1A-CMD-007: budget exhaustion + EFFECT_POSSIBLEはgrace後OUTCOME_UNKNOWN。
- M1A-CMD-008: local now=1000、retry_delay_ms=200、profile backoff=500でinternal retry_not_before=1500。wire / public absolute retry timeは0件。
- M1A-CMD-009: internal retry timerのepochとcurrent / deadline epochが不一致なら、now数値が大きくてもdispatch 0、deadline verdictはINDETERMINATE。
- M1A-CMD-010: local now + effective retry delay overflowでnew timer / attempt 0、NINLIL_REASON_COUNTER_EXHAUSTEDでfail closed。
- M1A-CMD-011: accepted-send current ATTEMPT_RECEIPT_TIMEOUTはEFFECT_POSSIBLE + AWAITING_EVIDENCE、immediate RETRY_WAIT / FAILED_DEFINITIVE 0。
- M1A-CMD-012: stale old-attempt ATTEMPT_RECEIPT_TIMEOUTはcurrent attempt / budget / timer / Outcomeを変更しない。
- M1A-CMD-013: NO_EFFECT_PROVEN + RETRY_SAME_AFTER Dispositionはbudget/deadline guard成立時だけinternal RETRY_WAIT / public WAITING_WINDOW。
- M1A-CMD-014: EFFECT_POSSIBLE timeout後でもAPPLY_IDEMPOTENTまたはAPPLICATION_DEDUPのexact identity guard + budget/deadline成立ならnew logical attempt。Old attempt Receiptは引き続受理。
- M1A-CMD-015: EFFECT_POSSIBLEでsafe apply-contract / budget / deadline guardのいずれか不成立ならsend 0、evidence closeまで不明ならOUTCOME_UNKNOWN。
- M1A-CMD-016: exact Disposition matrixのCAPACITY_EXHAUSTED / NO_EFFECT_PROVEN / RETRY_SAME_AFTERはbounded retry、OUTCOME_UNKNOWN / EFFECT_POSSIBLE / RETRY_OPERATOR_ACTIONはautomatic retry 0。
- M1A-CMD-017: remote cancelはdedicated cancel ID / prepare / entropy allocationがexactly 1。NEVER_INVOKEDまたはWOULD_BLOCK_RETRYABLEからfresh TxPermit取得後、Bearer call前にINVOKED_CLOSEDをFULL commitし、WOULD_BLOCKの間だけsame ID/messageでsend再実行、new attempt / entropy 0。
- M1A-CMD-018: Endpoint ABSENTまたはINBOX_COMMITTEDのcancelはtombstone + FENCED resultをcommitし、後着APPLICATION callback 0。
- M1A-CMD-019: Endpoint DELIVERY_STARTED / token / result / recovery後のcancelはTOO_LATE_EFFECT_POSSIBLE、effect rollback 0。
- M1A-CMD-020: Controller FENCED CANCEL_RESULTはCANCELLED_BEFORE_EFFECT、TOO_LATE resultはdispatch fenceを維持しevidence closeまで不明ならOUTCOME_UNKNOWN。
- M1A-CMD-021: same logical timeのdurable-ingress済みrequired ReceiptはCANCEL_RESULT / local cancelより先にcommitされ、terminal Outcomeをcancelで反転しない。
- M1A-CMD-022: duplicate same cancel attempt / bindingはcached CANCEL_RESULTを再送するだけでcallback / tombstone / attempt追加0。
- M1A-CMD-023: cancel APIはproviderをdrainせず、API開始前にlocal durable ingress済みのmessageだけをpriority対象にする。
- M1A-CMD-024: cancel sendの直前result=WOULD_BLOCKをWOULD_BLOCK_RETRYABLEへFULL commit済みならrestart後もsame attempt/messageでretry可能。Pre-send INVOKED_CLOSED commit後のcrash、WOULD_BLOCK以外、possible-delivery observation後はINVOKED_CLOSEDを復元しsend 0、result不足はPENDING。
- M1A-CMD-025: wrong cancel attempt IDまたはreverse source/target/service/digest/generation不一致のCANCEL_RESULTはbounded invalid observationだけでcancel state / Outcome不変。
- M1A-CMD-026: WOULD_BLOCKが3回続いた後の4回目cancel sendまで、4個のpermit IDはすべてfreshかつ相互に異なり、cancel attempt/message bindingは同一。最初の3回は各invoke前にINVOKED_CLOSED、そのreturn後にWOULD_BLOCK_RETRYABLEをcommitする。4回目のUNAVAILABLEでgateはINVOKED_CLOSEDのまま、5回目send / permit acquireは0。
- M1A-CMD-027: cancel result poison bufferを4 semantic kindで検査し、kind/reason/current_outcomeが12章matrixへ一致。Persist済みcancel kindは後続terminalより優先し、cancel自身でfenceしたrepeatをALREADY_TERMINALへ変えない。
- M1A-CMD-028: TX_GATE OK/TEMPORARY/DENIED/contract-fenceとBearer全status/output shapeを12章closed matrixへ写像し、attempt消費、effect certainty、permit release、retry/terminal、healthがexact一致する。
- M1A-CMD-029: ordinary send後/observation前crashはsame attempt ID/immutable bytesだけをfresh permitで再invokeし、receiver dedupでcallback/effect最大1。Observation commit済み/unknown未解決はadditional send0。
- M1A-CMD-030: cancel/resume/discardはledger/lookup後trusted clock exactly1でalready-durable earlier correctness timerをcatch-upし、exact same-timeだけpriority。Clock errorはresult zero/INVALID、mutation/Port side effect0。

### Attempt identity

- M1A-ID-001: attempt prepareの最初のcandidateがvalid non-zero uniqueならentropy.fill(16) 1回、attempt index + record + budget消費を同じFULL commit。
- M1A-ID-002: all-zero、collision、all-zero、validの順ならdraw 4回目を使い、最初の3 candidateでattempt / send 0。
- M1A-ID-003: 4 candidateが全てport failure / partial / zero / collisionのいずれかならNINLIL_E_ENTROPY、NINLIL_REASON_OUTCOME_UNKNOWN entropy health causeをaddし固定priorityからDEGRADEDを導出、attempt record / budget / permit / send 0。
- M1A-ID-004: collision lookup storage failureはNINLIL_E_ENTROPYに変換せずstorage statusでfail closed、send 0。
- M1A-ID-005: duplicate network deliveryは既存attempt IDを維持しentropy draw 0、logical retryはnew unique ID。Restart後もretained indexとcollisionしない。
- M1A-ID-006: remote cancel attemptもsame max-4 ruleを使い、Application attempt IDとcollision / reuseしない。

### Endpoint and Receipt

- M1A-END-001: inbox commit前にRECEIVEDを発行しない。
- M1A-END-002: DELIVERY_STARTED commit前にcallbackを呼ばない。
- M1A-END-003: result cache commit前にAPPLIEDを発行しない。
- M1A-END-004: duplicate deliveryはcached resultへ収束し、effectを重複させないかapply contractどおりreconcile。
- M1A-END-005: effect後/result前crashでAPPLIEDを捏造しない。
- M1A-END-006: Receipt commit failure時にSATISFIEDを公開しない。
- M1A-END-007: token context ID / generation / clock epoch / expires-at、DELIVERY_STARTED、delivery bindingをFULL commitする前にcallbackを呼ばない。
- M1A-END-008: callbackがDEFERを返した後、新しいtoken commitを要求せず既存durable tokenを保持。
- M1A-END-009: expiry前delivery_completeはresult commit + token expiry後にactive token resource解放。
- M1A-END-010: delivery_completeとtimeoutが同時刻ならdelivery_completeを先にcommit。
- M1A-END-011: timeoutはtoken expiry + RECOVERY_REQUIREDをatomic commitし、active token resource解放。
- M1A-END-012: timeout後retention中のlate delivery_completeはNINLIL_E_INVALID_STATE、retention後はNINLIL_E_NOT_FOUND。
- M1A-END-013: timeoutと同時のstorage failureではtokenをsuccess完了せず、recoveryでauthoritative stateへ収束。
- M1A-END-014: on_reconcile KNOWN_RESULTはresult commit後だけReceipt。
- M1A-END-015: on_reconcile REDELIVERはnew token generationでcallback。
- M1A-END-016: on_reconcile RETRY_LATERはout result/evidenceを一切読まず、trusted local now + descriptor fixed retry_backoffだけでbounded RECONCILE_WAIT。clock/overflow failureではtimer 0。
- M1A-END-017: on_reconcile OUTCOME_UNKNOWNはpositive Receiptなし。
- M1A-END-018: callback前token commitの各write point crashでapplication callback invocation 0。
- M1A-END-019: DEFER中process crashは旧tokenをexpired retentionへ移しRECOVERY_REQUIRED。
- M1A-END-020: fixture L=8でraw evidence 8件後のhigher-stage Receiptはsummaryのhighest/latestへatomic反映し、raw detailは8件のまま。
- M1A-END-021: fixture L=8でraw evidence 8件後のsame/highest-stage new materialはlatest data/digest/ingress sequenceとoverflow countへ集約。
- M1A-END-022: exact duplicateはduplicate count/record revisionだけを増やし、stage/terminal/event spool revisionを変更しない。
- M1A-END-023: fixture L=8でterminal後の9件目late Receiptはlate flag/countを更新し、terminal Outcomeを反転しない。
- M1A-END-024: evidence counter overflowはcounter_saturatedを立て、higher-stage/latest evidence処理を継続。
- M1A-END-025: 最初のcallback tokenはcontext_id = transaction_id、generation=1、clock_epoch_id / expires_at_msはcallback前durable markerとexact match。
- M1A-END-026: reconcile REDELIVERではcontext_idとtransactionを維持し、callback invocation count / token generationを2へchecked incrementして旧tokenをexpiredにする。
- M1A-END-027: known context / generationのactive tokenでclock epochまたはexpires-atを変えたcompletion、およびretention中のstale generationはNINLIL_E_INVALID_STATE。matching recordのない別Runtime / random contextはNINLIL_E_NOT_FOUND。
- M1A-END-028: prior callback invocation count=UINT64_MAXではnew token / callback 0、RECOVERY_REQUIRED + NINLIL_REASON_COUNTER_EXHAUSTED。
- M1A-END-029: sync callback resultがtoken expiryと同時刻ならresultを先にcommit。expiry超過またはclock epoch changeではsync success 0、RECOVERY_REQUIRED。
- M1A-END-030: SHA-256(empty)とSHA-256(non-empty exact evidence bytes)をinternal evidence digestとし、public / wireのapplication申告hash fieldに依存0。
- M1A-END-031: CALLBACK_FATALはtoken invalidation + active slot release + RECOVERY_REQUIRED / EFFECT_POSSIBLE / NINLIL_REASON_APPLICATION_FAILEDをFULL commit、health DEGRADED、Receipt 0。
- M1A-END-032: unknown callback actionまたはinvalid COMPLETE resultは同じrecovery commitをNINLIL_REASON_CALLBACK_CONTRACTで行い、same Runtime instanceの再callback 0。
- M1A-END-033: fatal/contract recovery commit failureまたはCOMMIT_UNKNOWNはReceipt / redelivery 0、health DEGRADED、storage recovery後のauthoritative token stateへ収束。
- M1A-END-034: unknown reconcile actionまたはinvalid KNOWN_RESULTはRECOVERY_REQUIREDを保持し、result / Disposition / Receipt 0、same recovery passの再callback 0。
- M1A-END-035: delivery_count / token generation / prior_callback_invocationsはUINT32_MAXを超えてもuint64で一致し、narrowing 0。Prior=UINT64_MAX-1はgeneration UINT64_MAXを1回発行可能、prior=UINT64_MAXの次incrementだけfail closed。
- M1A-END-036: lower-stage exact duplicateはduplicateだけ、lower-stage new materialはraw/overflowとvalid countへ保存するがhighest/latest stage/dataを巻き戻さない。
- M1A-END-037: same highest stageのmaterialはevidence-time epoch/valueでなくController durable ingress sequenceが大きい方をlatest fieldsへ採用する。異なるclock epoch、UNCERTAIN evidence timeでも数値比較0。
- M1A-END-038: admissionはsummary + raw L fixed-size physical cellとreplacement journal headroomをmaterializeする。不足時admit 0、成功後のunrelated Storage fullでlate cell updateをNO_SPACEにしない。
- M1A-END-039: Event spool revision MAX terminal後のunique/duplicate late evidenceはevidence/record revisionだけを更新しspool revision MAX、Outcome/tombstone/payload release不変。

### EventFact vectors

- M1A-EVT-001: local admission commit前にADMITTEDを返さない。
- M1A-EVT-002: spool fullではNINLIL_REASON_CAPACITY_EXHAUSTED、Ninlil ownershipなし。
- M1A-EVT-003: EventFactにEFFECT_DEADLINE / EVIDENCE_CLOSE timerを生成しない。
- M1A-EVT-004: 8回目のattempt timeout後にPARKED_RETRY、public reason=NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED、event_park_cause=NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT、payload保持、transaction active。
- M1A-EVT-005: PARKED_RETRY中はtimerだけで9回目を作らない。
- M1A-EVT-006: exact same epoch/flagまたはolder Bearer availability epochはno-opでcycleをresetしない。Same epoch/different flagはprovider contract failureでnamespace/Event不変。
- M1A-EVT-007: strictly greater Bearer availability epoch + available=1 + allowed park causeはsummary + new cycle + consumed epochをatomic commitし、attempts_in_cycle=0。Strictly greaterでもavailable=0はnamespaceだけ更新しcycle 0。
- M1A-EVT-008: same resume operation ID / same digestはNINLIL_EVENT_RESUME_ALREADY_RESUMED、different digestはNINLIL_EVENT_RESUME_CONFLICT。
- M1A-EVT-009: stale spool revisionのresumeはstate不変。
- M1A-EVT-010: PARKED_RETRY中のrequired ReceiptはSATISFIED + RELEASED。
- M1A-EVT-011: discard audit commit前はpayloadを削除しない。
- M1A-EVT-012: discard commit成功はFAILED_DEFINITIVE / NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT + DISCARDED。
- M1A-EVT-013: valid required Receiptとdiscardが同時刻ならSATISFIED + RELEASED、discardはNINLIL_EVENT_DISCARD_ALREADY_RELEASED。
- M1A-EVT-014: discardとresume / Bearer availability epochが同時刻ならDISCARDED、new cycleなし。
- M1A-EVT-015: discard後のrequired Receiptはlate evidence、terminal Outcome不変、payload復元なし。
- M1A-EVT-016: TRANSPORT_CUSTODY_ACCEPTEDだけではspool解放なし。
- M1A-EVT-017: EventFact cancelはNINLIL_E_UNSUPPORTED、spool不変。
- M1A-EVT-018: active中に記録したBearer availability epochのduplicateは、後からparkしてもresume理由にならない。
- M1A-EVT-019: APPLICATION_REMEDIATION parkはBearer availability epochだけでresumeせず、operator resumeを要求。
- M1A-EVT-020: stale attemptのATTEMPT_RECEIPT_TIMEOUTはcurrent cycleを変更しない。
- M1A-EVT-021: recent 4 cycleを超えるsummaryはfixed cumulative summaryへ畳み込み、resource上限を超えない。
- M1A-EVT-022: retry_cycle_id / cumulative counter overflowはpublic reason=EVENT_RETRY_CYCLE_PARKED / cause=COUNTER_EXHAUSTEDでparkを維持し、diagnosticにNINLIL_REASON_COUNTER_EXHAUSTEDを保持。
- M1A-EVT-023: PARKED_RETRY snapshotはBearer/Application/counterの詳細にかかわらずpublic reasonをEVENT_RETRY_CYCLE_PARKEDに固定し、詳細はevent_park_causeだけで返す。
- M1A-EVT-024: Runtime resource capacity_epochが増えてもEvent retry cycleはreset 0。Bearer availability_epochとの数値比較0。
- M1A-EVT-025: same resume operation/digest replayはcurrent state / stale expected revisionを評価する前にledger hitしALREADY_RESUMED、cycle/revision再変更0。
- M1A-EVT-026: resume ledgerのoperation IDをdiscardがdifferent digestで再利用すると、current state / revisionに関係なくexact conflict、mutation 0。
- M1A-EVT-027: 8 distinct resume operations後の9th unseen IDはNINLIL_EVENT_RESUME_LIMIT_EXHAUSTED / NINLIL_REASON_CAPACITY_EXHAUSTED、state / spool revision / ledger不変。既存8 ID replayは成功。
- M1A-EVT-028: same discard operation/digest replayはstate / revisionより先にledger hitしALREADY_DISCARDED、different digest/kindはDISCARD_CONFLICT、payload二重解放0。
- M1A-EVT-029: accepted-send current ATTEMPT_RECEIPT_TIMEOUTはEFFECT_POSSIBLEを保持するが、same event ID / key / digest dedup bindingでcycle内のnew attemptをfixed backoff後に許す。
- M1A-EVT-030: NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT / NINLIL_EVENT_PARK_CAUSE_BEARER_UNAVAILABLE / NINLIL_EVENT_PARK_CAUSE_CAPACITY_UNAVAILABLEだけがfresh availability epoch + `available=1`でresume可能、NINLIL_EVENT_PARK_CAUSE_APPLICATION_REMEDIATION / NINLIL_EVENT_PARK_CAUSE_COUNTER_EXHAUSTEDは不可。
- M1A-EVT-031: resume/discard ledger reservation不足はEvent admission REJECTED / CAPACITY_EXHAUSTED、admission後のsilent ledger eviction/reuse 0。
- M1A-EVT-032: COUNTER_EXHAUSTED causeへのunseen resumeはNOT_RESUMABLE / COUNTER_EXHAUSTED、current cycle/revision echo、mutation/ledger消費0。Known resume reason 5値は他の4 resumable causeすべてでaudit-onlyとして同じ成功guardを使う。
- M1A-EVT-033: Tx Gate TEMPORARYはcycle内fixed-backoff retry、8thだけCYCLE_EXHAUSTED。Application Bearer WOULD_BLOCK/UNAVAILABLEはattemptを戻さずpartial cycleを即時BEARER_UNAVAILABLE park、DENIEDはAPPLICATION_REMEDIATION、valid CAPACITY_EXHAUSTED DispositionはCAPACITY_UNAVAILABLE。
- M1A-EVT-034: Bearer CORRUPT/EMPTY/unknown/invalid OK outputはfalse no-sendにせずEFFECT_POSSIBLE + AWAITING_RECEIPT、Runtime DEGRADEDで、required Receipt/discard前のspool release 0。
- M1A-EVT-035: possible-delivery corrupt/invalid observationもcurrent attempt timeoutでsafe retryし、8th timeoutはattempt-timeout primary hook 1組でsummary + PARKEDをatomic commitする。
- M1A-EVT-036: namespace new available epoch 1 commitからeligible PARKED Event N件をowner順に1件1 commitでfan-outし、partial crash/restartでも各Event最大1 consume。Active/ineligible Event一括update0。

### Step and capacity observability

- M1A-OBS-001: capacity snapshotはkind 1〜11を順番どおりexactly 11件返し、unused role entryもall-zero accountingで存在。
- M1A-OBS-002: 各entryはused + reserved <= limit、reservation→used / releaseの全boundaryで12章11.1 tableと一致。予約なしcallback/effect 0。
- M1A-OBS-003: blocked flagなしのpoll/release/restartでcapacity_epoch不変。Actual block後のsame-class availability improvement FULL commitだけ+1。
- M1A-OBS-004: resource capacity_epochとBearer availability_epochは同値でも別domainで、Event resumeはBearer epochだけをconsume。
- M1A-OBS-005: due-now timerだけならmore_work=1、has_next_wake=0。Due-nowとsame trusted epochのfuture durable timerが両方あればmore_work=1 / has_next_wake=1で最早future pointを返す。
- M1A-OBS-006: has_next_wake=0でepoch/time all-zero、1でepoch non-zero / wake > now。Clock uncertain / epoch mismatchは推測wake 0。
- M1A-OBS-007: delivery callback countをUINT32_MAX+1へ進めてもdelivery_count / generation / prior_callback_invocations / cumulative metricはuint64で一致。
- M1A-OBS-008: Event admission payload length=100ではEVENT_SPOOL_BYTES used=100 / reserved=2560 / total=2660。Resume 1回成功後はused=356 / reserved=2304 / total=2660。Required Receipt terminal後はused=256 / reserved=0、代わりに同Eventをdiscard成功したterminalではused=768 / reserved=0で、どちらもattempt/summary physical bytesを加算0。
- M1A-OBS-009: on_delivery workにcallback budget=1 / state-transition budget=1しかなければcallback / commit 0、workをqueueへ残しmore_work=1。Budget 1/2ならDELIVERY_STARTED commit後にcallbackへ入り、DEFERならunused second state reservationを同じstepへ返す。
- M1A-OBS-010: remote cancel sendにbearer-send budget=1 / state-transition budget=1しかなければpre-send gate commit / permit / send 0、more_work=1。Budget 1/2だけがpre-send INVOKED_CLOSED、actual send、post-return observationの順を許す。
- M1A-OBS-011: simultaneous NINLIL_REASON_STORAGE_IO、NINLIL_REASON_CALLBACK_CONTRACT、NINLIL_REASON_GRANT_PROVIDER_UNAVAILABLE causeではpriority 1のNINLIL_REASON_STORAGE_IOを返し、clearごとにpriority 3、5へ移る。Provider temporary failureはcause/reference countを変えず、全cause解消時だけNINLIL_HEALTH_OK / NINLIL_REASON_NONE。
- M1A-OBS-012: 12章のm1a_public_generated_zero exact 9 reasonsはSubmission、transaction/target、step health、management outputの全fixtureで出現0。Event park detailはevent_park_cause、public reasonはNINLIL_REASON_EVENT_RETRY_CYCLE_PARKEDだけ。
- M1A-OBS-013: step順はentry clock→recovery barrier→Bearer state→fixed owner cut→ring1/ingress1交互。Ingress copyは次stepからreduceし、continuous ingressで既存ownerをstarveしない。
- M1A-OBS-014: new rootだけowner sequenceを割当て、known reverse/duplicate inputはexisting ownerへattach。Earlier timeが先、exact same-timeだけpriority、epoch bytes比較0。
- M1A-OBS-015: cursorは12章micro-operation tableのexact commitへ1回だけ含め、same ownerを1 stepで再訪しない。Stale/no-opもcursor-only FULL/state budget1。
- M1A-OBS-016: Application sendはsend1/state1、remote cancelはsend1/state2。Application observation前crashはsame attemptだけをduplicate-safe再invokeし、cancelはINVOKED_CLOSEDで再invokeしない。

### Crash recovery vectors

- M1A-REC-001: prepared attempt crash後はattempt消費済みだがsend observationがなければ同じattempt ID/immutable messageをfresh permitで再invokeする。Observation commit/unknown解決前にnew attemptを作らない。
- M1A-REC-002: terminal transactionをoutboxへ戻さない。
- M1A-REC-003: PARKED_RETRYはrestartだけでHELD_READYへ戻さない。
- M1A-REC-004: clock uncertainty + undispatched CommandはEXPIRED/NINLIL_REASON_CLOCK_UNCERTAIN。
- M1A-REC-005: clock uncertainty + effect possibleはOUTCOME_UNKNOWN。
- M1A-REC-006: storage full recoveryでadmitted dataをcleanup対象にしない。
- M1A-REC-007: EventFact retry_cycle_id / attempts_in_cycle / last seen/consumed Bearer availability epochをrestartでrollbackしない。
- M1A-REC-008: discard各write point crash後はpayload+auditなし、またはno payload+audit+tombstone。
- M1A-REC-009: discard commit acknowledgement不明から同じoperation IDで1つのDISCARDEDへ収束。
- M1A-REC-010: EventFactはclock uncertaintyだけでOutcome / spool stateを変えない。
- M1A-REC-011: 08 / 12 registryの全named FULL boundaryでbefore/after crashをinjectし、old stateまたはnew stateの一方へ収束。未登録の独自hook / iterator-state hook 0。
- M1A-REC-012: namespace profile/capacity/4 counters initial commit、owner/input attachment、cursor-containing groupは各specific hook/COMMIT_UNKNOWNでall-or-none。Partial owner/index/counter0。

### M1b ALL_TARGETS forward contract

- M1B-GRP-001: 2/2 SATISFIEDだけaggregate SATISFIED。
- M1B-GRP-002: 1 SATISFIED + 1 activeはnon-terminalかつpartial progress。
- M1B-GRP-003: 全terminalで1 OUTCOME_UNKNOWNならaggregate OUTCOME_UNKNOWN。
- M1B-GRP-004: 1 SATISFIED + 1 CANCELLEDはFAILED_DEFINITIVE / NINLIL_REASON_M1B_ALL_TARGETS_NOT_MET_PARTIAL_EFFECT。
- M1B-GRP-005: late Receiptでaggregate terminal Outcomeを反転しない。

## M1a completion gate

M1a reducerは次をすべて満たした場合だけimplementation-readyです。

- 上記state、input、guard、priority、reasonがpublic typeまたはinternal canonical typeへ一意に写像されている。
- Mandatory test vectorがRuntime外部のdeterministic simulator harnessで再現できる。
- 全durable state boundaryが08 / 12のauthoritative named crash registryのexact hookへ対応し、未登録の独自hook名0。
- admission assuranceのfalse fieldを成功表示から省略しない。
- EventFact resume / discard API、operation idempotency、audit recordをpublic API referenceへ明記する。
- EventFactのNINLIL_NO_DEADLINEと8-attempt retry cycleをpublic typeとfixtureで固定する。
- target_count=1がAPI validationとtestで固定されている。
- late evidence、Outcome、spool stateを同じenumへ混ぜていない。

M1aの完了は、real radio、KGuard実機、remote capacity、期限内配送SLO、production durabilityを証明しません。
