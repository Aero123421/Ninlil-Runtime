# 08. Foundation Release

状態: Normative M1a implementation baseline<br>
予定release: Ninlil Runtime 0.1.0 experimental

## Release goal

Foundation Releaseは、KGuardやradioを一切importせず、次の2種類をrestart-safeに処理するGeneric Transaction Kernelです。

1. single targetの`DesiredStateCommand`をtarget applicationへ届け、`APPLIED`まで追跡する。
2. `EventFact`をoriginで保持し、controllerの`DURABLY_RECORDED`まで追跡する。

このreleaseの価値は「電波が飛ぶこと」ではなく、loss、duplicate、reorder、crashがあっても、所有権、identity、receipt、outcomeを正直に維持できることです。

## In scope

- public C ABI 0.1
- portable transaction/receipt/outcome core
- `CONTROLLER` / `ENDPOINT` rolesと外部simulator harness
- ServiceDescriptor registration
- `DesiredStateCommand` / `EventFact`
- concrete target 1件
- admission、idempotency、finite reservation
- restart-safe controller outbox
- restart-safe endpoint inbox/event spool/result cache
- Observation / Receipt / Delivery Disposition / Outcome separation
- cancellation、command deadline、EventFact no-deadline、late evidence
- POSIX SQLite storage port
- deterministic simulated bearer
- optional POSIX loopback bearer example（release gate外）
- fault/crash injection
- generic examples and conformance suite
- TEST identity/origin authorization、envelope binding validation、virtual Tx Gateのfail-closed boundary（cryptographic/session providerはM1a外）

## Out of scope

- Ninlil public radio wire format
- SX1262 / real LoRa TX
- production credential / Attachment handshake
- full Identity/Membership/Attachment/Route/Grant implementation
- destination selector、group/multi-target、`ALL_TARGETS`
- Cell Agent scheduler
- LatestState、MeasurementBatch、BoundedTransfer、ConfigRevision
- fragmentation
- counter-offer生成、offer保存/acceptance（enum/APIは予約し、M1aではunsupported）
- relay / multi-hop
- multi-parent / multi-controller HA
- Wi-Fi / USB production bearer
- OTA
- KGuard integration
- Japan deployment profile

Out-of-scope featureのenumやstubを「対応済み」と表示しません。Public APIが予約済みでも、呼出しは`NINLIL_E_UNSUPPORTED`を返します。

## Reference implementation choice

- public API: C11-compatible header
- reference core implementation: C++17
- public ABIにC++ typeを露出しない
- exception / RTTIを使用しないbuildをCIで検証する
- allocationは`ninlil_platform_ops_t`のbounded allocatorだけを使用する
- build: CMake
- POSIX persistence: SQLite
- simulator/test: C++17

ESP-IDF component化はM3ですが、portable coreはOS thread、filesystem、SQLite、dynamic exceptionに直接依存してはなりません。

## Target repository layout

```text
ninlil/
  CMakeLists.txt
  README.md
  include/ninlil/
    runtime.h
    service.h
    transaction.h
    platform.h
    version.h
  src/
    core/
    contract/
    storage/
  ports/
    posix/
      sqlite_storage/
      clock/
      entropy/
  simulator/
  examples/
    reliable_command/
    durable_event/
  tests/
    unit/
    conformance/
    crash/
    fuzz/
  schemas/
  compatibility-matrix.json
  requirements-traceability.yaml
```

CoreからSQLite、pthread、KGuard、legacy LinkOS、RadioLibを直接includeしてはいけません。

## Foundation public API

完全なtype、signature、ownership、threadingは[12-foundation-abi.md](12-foundation-abi.md)を正本とします。Foundation M1aで実装必須:

```text
runtime_create / destroy
service_register
submit
cancel_request
event_resume / event_discard
transaction_query / list
delivery_complete
runtime_step
capacity_snapshot / metrics_snapshot
```

`offer_accept` symbolとreserved result値はABIに存在しますが、M1aでは常に`NINLIL_E_UNSUPPORTED`です。`ADMITTED_SCHEDULED`と`COUNTER_OFFERED`をM1aが生成する経路はありません。

Foundationではsubscription APIを実装必須にしません。Callerは`transaction_list/query`とstep resultで状態を取得します。Event callback APIは、re-entry/lifetimeを十分検証した後のminor releaseへ送ります。

## Canonical identity and digest

- transaction ID: Runtime-generated random 128-bit value。storage内でcollision checkし、all-zero/collisionの場合は候補drawを合計最大4回行い、4件すべて無効なら`NINLIL_E_ENTROPY`。既存Runtimeはhealth `DEGRADED`とし、M1aは`HEALTH_FATAL`を生成しない。
- caller idempotency key: 1〜64 bytes、`source application instance + service identity(namespace + service ID)` scope。Descriptor revisionはscopeでなくcanonical digestへ含める。
- event ID: origin-generated 128-bit value。origin durable admission前に生成し、event retryで不変。
- attempt ID: Runtime-generated 128-bit value。再試行ごとに新規。
- content digest: algorithm ID + 32-byte SHA-256。
- canonical submission digest: descriptor revision、source、targets、deadline/evidence、family metadata、payload digestをlength-delimited encodingしてSHA-256。

Canonical encodingはtest vectorを持ち、platform languageのstruct paddingやmap iteration orderへ依存しません。

## Foundation resource profile

Profile ID: `NINLIL-FOUNDATION-SMALL-1`

### Controller

| Resource | Limit |
| --- | ---: |
| registered services | 16 |
| non-terminal transactions | 256 |
| targets per transaction | 1 |
| logical payload per submission | 1024 bytes |
| total durable outbox payload | 256 KiB |
| attempts per target | 8 |
| evidence records per transaction/target | 8 |
| retained terminal transactions | 2048 |
| idempotency key length | 64 bytes |
| counter-offers | 0（M2で追加） |

### Endpoint

| Resource | Limit |
| --- | ---: |
| registered services | 8 |
| non-terminal deliveries | 32 |
| logical payload | 1024 bytes |
| durable EventFact spool | 32 events / 32 KiB |
| persistent result cache | 64 entries |
| attempts per event retry cycle | 8。枯渇でdiscardせず`PARKED_RETRY` |
| retained Delivery Disposition | 64 |

### Common

| Resource | Limit |
| --- | ---: |
| ingress events processed per `step` | caller budget, max 64 |
| max callback work per `step` | caller budget |
| evidence data | 128 bytes |
| reason text in Core | none; reason code only |

Runtime configはprofileより小さくできますが、登録ServiceDescriptorのhard limitを満たさなければservice registrationを拒否します。Foundationではprofile上限を超えるruntime configを受理しません。

## Retention and deletion order

Default retention:

- non-terminal transaction: terminalまで削除禁止
- terminal transaction/evidence: 24 hours in simulator profile
- idempotency mapping: corresponding terminal retention終了まで
- endpoint result cache: max(24 hours, descriptor required dedup window)
- EventFact: required Receiptまたは監査付きexplicit operator discardまで。M1a EventFactは`NINLIL_NO_DEADLINE`
- Observation detail: 1 hour。以後bounded summaryへ集約可能

Storage pressure時の削除順:

1. expired detailed Observation
2. expired diagnostic detail
3. retention終了済みterminal transaction/evidence/idempotency mappingを同一cleanup transactionで削除
4. 新規replaceable dataのadmission reject（Foundationでは該当familyなし）
5. 新規command/eventを`CAPACITY_EXHAUSTED`でreject

Non-terminal transaction、unacknowledged EventFact、required evidence、active idempotency mappingをsilent deleteしません。

EventFact retry cycleが枯渇してもterminalへ移さず、origin spool上の`PARKED_RETRY`として保持します。Bearerのavailability state changeごとに増えるepochのうち、freshかつ`available=1`で通信可能性の改善を示す`availability_epoch`、またはoperator resumeで新cycleを最大8 attemptまで付与します。Degradation epochは保存しますがcycleを作りません。Runtime resourceの`capacity_epoch`と数値比較しません。Cycle付与はairtime/quotaを増やす権限ではありません。Explicit discardはreason、actor、event ID、last evidence、timestampをdurable auditした後だけspoolを解放します。

## SQLite POSIX port

Reference portは次を設定します。

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;
```

- 1 Runtime instanceにつき1 DB writer ownerを使用する。
- busy timeoutはtest/configでboundedにする。
- schema versionとmigration stateをmeta tableへ保存する。
- admission/event/resultのatomic groupは単一SQLite transactionを使用する。
- application payloadはBLOBとして保存し、secretをSQL logへ出さない。
- DB full/I/O/corruptionはAPI statusとRuntime degraded reasonへ変換し、successへfallbackしない。

Database table名とcolumn layoutはinternalであり、0.1のpublic compatibilityではありません。Conformanceはobservable behaviorとmigration contractを検査します。

## Simulated bearer contract

Simulatorはpublic wire byte formatを先取りしません。Typed logical envelopeをcopyし、次をfault scriptで制御します。

- deliver at virtual time
- drop
- duplicate N times
- reorder group
- corrupt digest/envelope metadata
- partition direction
- receiver unavailable/sleeping
- transport custody accepted/lost

各logical retry attemptは新attempt IDを持ち、logical transaction/event identityを維持します。ただしsend observation前crashのreinvokeとnetwork duplicateは同じattempt ID/immutable messageを維持し、receiver dedupでapplication effectを増やしません。

## Generic fixtures

### Reliable Command v1

```text
namespace: org.ninlil.examples
service: absolute-state
family: DesiredStateCommand
schema: absolute-state/1.0
payload: desired_state(u8) + generation(u64 little-endian)
required evidence: APPLIED
effect deadline: 5,000ms virtual time
evidence grace: 1,000ms
apply contract: absolute/idempotent
```

Endpoint exampleは`desired_state`と最後の`generation + transaction ID + APPLIED stage`を同一SQLite transactionへ保存します。

### Durable Event v1

```text
namespace: org.ninlil.examples
service: durable-event
family: EventFact
schema: durable-event/1.0
payload: event_kind(u16) + observed_sequence(u64)
required evidence: DURABLY_RECORDED
effect deadline: NINLIL_NO_DEADLINE
evidence grace: 0
origin admission: ORIGIN_WITH_GRANT fixture
```

Controller exampleはevent ID、source、digest、payloadを同一SQLite transactionへ保存し、そのcommit後だけReceiptを発行します。

## Named crash boundaries

M1aの**完全なhook registryとplacement contract**は[12. Foundation C ABI §17](12-foundation-abi.md#17-named-fault-hook-registry)を唯一の正本とします。Admission、attempt、delivery/callback、result/receipt、timeout/reconcile、Event retry/park/resume/discard、cancel、cleanup/recovery、capacity epochの各境界を含みます。他文書で一部のhookを例示してもregistryへの追加・削除にはなりません。

Fault hookはtest buildだけで有効ですが、production control flowをbypassする別実装を作りません。

## Foundation acceptance criteria

### Build/API

- C11 consumerとC++17 consumerがpublic headerだけでcompile/linkできる。
- CoreがKGuard/legacy/radio/platform private headerをincludeしない。
- exceptions/RTTI disabled buildが通る。
- allocator failureを全public allocation pointでtestできる。

### Command

- happy pathでAPPLIED後だけSATISFIED。
- duplicate/loss/reorder後もlogical transactionは1つ。
- controller restart後にoutboxを再開する。
- endpoint restart後にfixture stateを二重変更しない。
- effect後cache前crashはapply contractどおりreconcileし、false successを出さない。
- late APPLIEDはevidenceへ残るがdeadline verdictを反転しない。

### Event

- origin commit前にadmittedとして外部へ返さない。
- controller commit前にDURABLY_RECORDEDを返さない。
- duplicate eventはbusiness recordを増やさない。
- required Receipt前のorigin restartでeventを再送する。
- spool fullはsilent dropせずlocal admissionをreason付き拒否する。
- retry cycle枯渇後もEventFactを保持し、fresh bearer `availability_epoch + available=1`またはoperator resumeで同じevent/transaction identityのまま再開する。
- explicit discardはaudit commit前にspoolを解放しない。

### State/error

- descriptor revision更新を跨いでもsame idempotency key/same digestは同じtransactionを返す。
- same key/different digestはIDEMPOTENCY_CONFLICT。
- terminal Outcomeは全late inputで不変。
- cancelの4結果をfixtureで再現できる。
- wrong thread、callback re-entry、buffer不足、storage fullを構造化errorにする。
- submitted/admitted/rejected/satisfied/expired/unknownを別metricで出す。

### Test gate

- 07章のPR gateが通る。
- fixed regression scenarioと10,000 simulator seedsでinvariant violation 0。
- 全named crash boundaryでsilent custody/ownership loss 0、duplicate logical transaction/business record 0。
- duplicate transport dispatchは許容し、application effectはapply contractどおり再適用またはunknownになる。
- ASan/UBSan error 0。
- exposed parser fuzz smokeでcrash/hang 0。

## Definition of Done

Foundation Releaseは、上記acceptanceをrelease commitで満たし、generic examples、API reference、porting note、known limitationsを含むときだけ完了です。

Legacy display/leakが動くこと、実radioが送信できることはFoundation完了条件ではありません。
