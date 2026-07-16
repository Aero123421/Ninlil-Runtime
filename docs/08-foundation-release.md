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

Host implementation location（port-owned; public ABI外）:

- factory: `ports/posix/include/ninlil_posix_sqlite_storage.h`
- provider: `ports/posix/sqlite_storage/`
- opaque storage namespace bytes（1..255）は path 文字列へ解釈せず、configured database file 内の BLOB `namespace` column で分離する。
- WAL/SHM の pathname authority を一意にするため、provider create は configured main DB を `O_NOFOLLOW|O_CLOEXEC` で先に開き、`st_dev/st_ino` から同一directoryの authority sidecar名を決める。sidecarは `O_NOFOLLOW|O_CLOEXEC`、regular、link count 1、**current effective UID所有、exact mode `0600`**を検査し、nonblocking exclusive `flock` 後および後続authority境界にもpath↔fd identity/owner/modeを再検証する。group/other read/write/executeはrepairせず拒否する。main DBのhardlink/final symlinkはSQLite open前に拒否し、main/sidecar双方のpath replacementをSQLite open後とdurable mutation前にfail-closed検出する。leaseはDB-wide、process crash-safeで、destroyはunlock/closeするがunlinkしない。PID行とper-namespace lease pathnameは使わない。main DBへのdirect `flock`はmacOSでSQLite自身のrecord lockと競合する実測により禁止する。
- opaque handle/txn/iterator は64-bit Linux/macOSのflat address profileで、create時に`PROT_NONE`の16 TiB virtual token arenaを予約し、provider lifetime中に同じarena addressを再発行しない。arena addressはdereferenceせず、範囲とactive slot identityだけを検査するため、fabricated/stale tokenをfail-closedにしつつ操作回数比例のheap増加を作らない。32-bitまたはarena予約不可はcreate時fail-closed。Foundation public ABIは変更しない。generation / lease-token は pure monotonic advance（max 引数、no wrap）で、production storage は `UINT64_MAX` 固定 domain を使う（runtime ceiling 注入 API なし）。
- **Supported host diagnostics**（port factory header、same-thread、内部lockなし）: `live_handles` / `live_transactions` / `live_iterators` は live opaque token 数の snapshot、`connection_fenced` / `lease_tokens_fenced` は permanent fail-closed flag、`simulate_crash` は live handle/lease を process crash 相当に破棄（file unlink や committed bytes の取り消しはしない、caller 保持 token は stale）。これらは Core public ABI ではなく host observability である。
- capacity は put 毎ではなく commit 直前の最終 transaction view の net で判定する（docs/14）。
- schema v1 は exact columns/storage classes、STRICT、WITHOUT ROWID、exact meta rowsに加え、`sqlite_master` objectをexact 2 tablesへclosed-list化する（WITHOUT ROWIDなのでrequired autoindexは0）。trigger/view/追加index/`sqlite_stat*`/`sqlite_sequence`/legacy `ninlil_lease`、unknown/partial schema、extra table/column は migration・dropせず拒否する（auto-upgrade なし）。
- **Durable namespace persist ordering（schema TOCTOU closure）:** `persist_namespace_view` は `BEGIN IMMEDIATE` で write lock を先に取得し、**同じ transaction 内**で closed schema definition を再検証し、続けて path/fd/`nlink`/lock authority identity を再検証してから DELETE/INSERT を行い、最後に `COMMIT` する。schema 不正は **mutation 前**に `ROLLBACK`（autocommit 確認）し、`CORRUPT` を返して connection を fence する。validation→`BEGIN` の間隙に外部 connection が trigger を注入できる順序は禁止する。provider が write lock を保持している間の外部 schema mutation は SQLite 側で BUSY になるか、mutation 前再検証で拒否され、既存 durable row は不変である。raw 外部 SQLite access は support 対象外であり、closed-shape 再検証は defense-in-depth であって raw 同時書込みを FULL OK 成功として正当化しない。
- **Pathname rename/replacement revalidation:** main DB と authority sidecar の path↔fd `st_dev`/`st_ino`/`nlink` と sidecar owner/mode/lock authority は、少なくとも (1) `BEGIN IMMEDIATE` 成功後、(2) DELETE/INSERT mutation 直前、(3) `COMMIT` 直前、(4) `COMMIT` 成功かつ autocommit 確認後・public OK 返却前、で再検証する。**pre-COMMIT 再検証で観測した差替え**は `ROLLBACK`（autocommit で non-commit を確認できる場合）+connection fence+`CORRUPT`（I/O 不能時は `COMMIT_UNKNOWN`）。**最後の pre-COMMIT 再検証の直後から `COMMIT` 完了までの差替え**、および **`COMMIT` 成功後の差替え**は post-COMMIT identity でのみ観測され、`COMMIT_UNKNOWN`+connection fence とし、**決して OK を返さない**。再検証点の間隙は原子的に閉じない。成功返却直前の identity 一致は、当該 FULL commit が support precondition 下で linearize された evidence である。
- `busy_timeout_ms` は `INT_MAX` 以下だけを受理し、外部 SQLite writer lock に対する実時間 bounded wait を host test で検証する。
- custom SQLite VFSを持たない本sliceは、live中に外部processがmain DB/authority sidecarをrename/unlink/chmod/chownしないlocal-volume運用をsupport preconditionとする。parent directoryはeffective UIDがprivate `0600` sidecarを作成・openでき、untrusted userがlive pathを置換できないことを要する（world/group-writable directoryのsticky bitだけでは保証を拡張しない）。上記再検証点での置換・sidecar owner/mode drift は fail-closed に検出するが、**linearization 後の変更**および **再検証点間の adversarial pathname mutation を原子的に防ぐ**ことまでは主張しない。OS 上の uncooperative rename/replace を完全防止できないため、public durability claim は「support precondition を満たす local volume 上で、provider が OK を返した時点の identity 証拠付き SQLite durability boundary」までに狭める。host test の決定的 interleave は production TU / install API に seam を置かず、test target 専用 interpose に隔離する（下記 linkage matrix）。
- FULL durability claim は上記 PRAGMA 下の SQLite durability boundary と、成功返却直前 identity 一致まで。filesystem/hardware が flush を偽る範囲、および linearization 後の path 差替えは保証外で port profile へ明記する。
- **SQLite linkage / install / test backend matrix（normative host profile）:**
  | Platform | Production link | Installed consumer | Host tests (`NINLIL_BUILD_TESTS=ON`) |
  | --- | --- | --- | --- |
  | Linux + shared `libsqlite3.so` | supported | supported（`find_dependency(SQLite3)`） | supported（RTLD_NEXT dlsym interpose） |
  | Linux + static `libsqlite3.a` | supported | supported（export が Threads/`dl`/`m`、必要時 ZLIB を PUBLIC/INTERFACE 伝播し `NinlilConfig` が `find_dependency` 再現） | supported（GNU/Clang `ld --wrap` interpose; 非対応 linker は configure fail-fast） |
  | macOS + shared/dylib | supported | supported | supported（dlsym interpose） |
  | macOS + static `.a` | **unsupported**（install/export を claim しない） | **unsupported** | **unsupported**（tests-on は configure fail-fast; tests-off でも production static claim なし） |
  CMake `NINLIL_SQLITE_LINKAGE` は exact closed set `AUTO|STATIC|SHARED`（それ以外は configure FATAL）。**AUTO は path を確実に分類できない場合 shared 推測を禁止し FATAL**。明示 `STATIC` のみ、operator が `SQLite3_LIBRARY` で指した opaque な既存 regular file を受け入れ得る。static Linux の system deps は pkg-config `--static` と archive 未定義シンボル検査で閉じる。
  **出荷 artifact path hygiene（非 sanitizer production）:** installed archive は GCC/Clang/AppleClang の `-ffile-prefix-map`/`-fdebug-prefix-map`（必要時 `-fmacro-prefix-map`）+ `-gno-record-gcc-switches` で source/binary absolute root を remap する。**GNU のみ** feature-checked `-gdwarf-4` を PRIVATE 適用し DWARF5 `.debug_line_str` の build cwd 漏えいを閉じる。Clang/AppleClang は prefix-map + `-fdebug-compilation-dir=.` で non-sanitizer 出荷 needle を 0 にする（全 compiler への無条件 `-gdwarf-4` や relpath compile launcher は採用しない）。Debug を strip しない。非 sanitizer では archive/`ar x` 後 object の `strings`（Linux では `readelf` inventory 併用）で source/binary/nested build root・prefix-map flag 再埋込が 0。CI は Ubuntu GCC 既存 gate に加え **Ubuntu Clang 非 sanitizer** の厳格 archive scan と **macOS AppleClang** 標準ツール（`strings`/`ar`）scan を必須化する。
  **Sanitizer artifact は非出荷:** `NINLIL_ENABLE_SANITIZERS=ON` の ASan/UBSan buildと、対応toolchainで有効になった `NINLIL_ENABLE_POINTER_COMPARE_SANITIZER=ON` buildはcoverageを下げない。installed consumer は package/install/`find_package`/link/run を維持する。ASan global descriptor が absolute `-c` source path を `.rodata` に埋めるのは prefix-map では除去不能なため、**明示的に有効化され、toolchain確認も完了したsanitizer instrumentationのときだけ** archive/object hygiene scan をskipする（compiler推測・暗黙fallback不可。検査コード削除やASan globals無効化は禁止）。出荷hygieneは非sanitizer gateが保証する。
  static installed consumer は `SQLite3_LIBRARY=libsqlite3.a` 固定と `ldd`/`readelf` で `libsqlite3.so` 依存 0 を assert する。
- この port 単体の存在は public Runtime body / M1a complete / field-ready を意味しない。

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
