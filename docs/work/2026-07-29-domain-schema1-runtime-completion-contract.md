# Domain schema 1 Runtime completion contract（freeze candidate）

状態: **PROPOSED / implementation gate — Accepted ADRではない**

対象: `NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON` の public Host
Runtime path。ADR-0022、`docs/12-foundation-abi.md`、
`docs/17-foundation-domain-store.md` に優先しない。矛盾時は本書を修正し、
Runtimeはfail closedする。

## 0. 現在の強制fail-closed状態

`src/runtime/domain_schema1_startup_owner.h` のprivate implementation constant
`NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY` は `0u` である。Domain bindingをONにした
有効configの`ninlil_runtime_create()`はpure validation直後に
`NINLIL_E_UNSUPPORTED`を返し、allocator、execution、clock、entropy、Storage、
Bearer、TX gate、origin authorizationを呼ばず、public handleをNULLのままにする。

`domain_schema1_publication_not_ready`がこの契約をnormal/ASanで検査する。Feature-ON
buildでは、create成功を前提にするV1-LAB public Runtime CTestは`DISABLED`と明示表示し、
expected fail-closedを回帰失敗へ混ぜない。実行ファイルは引き続きcompileする。
Default-OFF buildの`v1_runtime_spine`等はDISABLEDにせず、従来挙動の回帰authorityとして
実行する。Readinessを`1u`へ変えるchangeは、このroutingの削除と§8全試験の
Domain-ON green化を同時に行わなければならない。

## 1. 解決するP0

現行候補はformat-2 Domain bootstrap、SERVICE、SERVICE_QUOTAと、format-1 LABの
`NRS` / `TX` / `CN` / `DS` / `EV` / `OC` / `ES` / `ER` / `ED` / `RT` /
`RV` / `BS` / `AP`を同じStorage namespaceへ書く。これはADR-0022 D22-01、
D22-04、D22-05と、`runtime_v1_transaction_codec.h`のnamespace分離要件に反する。
Fresh createは通っても最初のoperational write後のrestartでCanonical scannerが
MIXED/CORRUPTを検出するため、public Runtimeとして成立しない。

完成条件は次の3点を同時に満たすこととする。

1. Domain-ON writerはcanonical family 1–6 recordとwitnessだけを書く。
2. LAB sourceはread-only export/quarantineだけで、Domain publication authorityにも
   dual-write先にもならない。
3. `v1_runtime_spine`のpublic behaviorをDomain recordからrestart復元できる。

DomainをOFFへ戻す、LAB rowをCanonical scannerのallowlistへ加える、同じlogical
operationを2 namespaceへbest-effort dual-writeする、またはLAB rowをopaque BLOBへ
包む案は完成条件を満たさない。

## 2. Namespaceとmigrationのclosed boundary

### 2.1 Runtime-owned namespace

1 public Runtime instanceはcreate configのexact 1 namespaceを所有し、そのnamespaceの
active writer leaseもexact 1つだけ取得する。Domain-ONではそのnamespaceをformat 2
Domain専用とし、LAB operational keyのread/writeを0にする。

Wi-Fi credential、Attachment/M4、radio replay/context、relay/multi-parent等、
Domain catalog外のownerは、各accepted contractが定める別namespaceを明示的にopenする。
Runtime namespaceの接頭辞を暗黙流用しない。派生namespaceを必要とする場合はcallerが
exact bytesを指定し、collision-freeであることをintegrationが保証する。

### 2.2 LABからのcutover

ADR-0022 D22-05どおり、in-place conversionとautomatic importは行わない。

1. source LAB namespaceを同じREAD_ONLY transactionで完全exportする。
2. complete artifactをbusiness authority/operatorがreconcileする。
3. 別の0-row namespaceを明示選択し、format-2 T0からbootstrapする。
4. service descriptor/callbackをpublic APIで明示re-registerする。
5. inflight workは、authoritative business systemが新しいlogical submissionとして
   再投入する。旧transaction ID、quota、callback effect、custodyを推測して移植しない。
6. source archive/deleteはRuntime外の別authorizationとする。

Migration toolの成功はDomain Runtime createの成功条件ではない。Format 1、mixed、
partial export、未完了artifactを指定したDomain createはwrite/Bearer/callback/publish 0で
拒否する。

## 3. Canonical operational writer inventory

下表はlegacy rowのbyte変換表ではない。Public operationのsemantic truthを、
既存Domain catalogへ直接materializeするwriter置換表である。各行は該当する
`docs/17` operation-kind witnessのsingle FULL groupに入る。

| Legacy projection（削除対象） | Canonical Domain truth |
| --- | --- |
| `NRS` SERVICE ledger | `SERVICE(10)`、`SERVICE_QUOTA(11)`、service owner `RESERVATION(23)`、capacity SERVICE、HEAD_INDEX、kind 1 witness |
| `TX` admission snapshot | `TRANSACTION_ANCHOR(20)`、`TRANSACTION_SEQUENCE_INDEX(21)`、`TRANSACTION_STATE(22)`、transaction `RESERVATION(23)`、`SCHEDULER_OWNER(26)`、必要な`IDEMPOTENCY_MAP(24)` / `EVENT_ID_MAP(25)`、capacities、kind 2/3 witness |
| `CN` | `CANCEL_STATE(33)`とowner/anchor/state/capacity companion、kind 12/13 witness |
| `DS` / `AP` | `ATTEMPT(31)`、`ATTEMPT_ID_INDEX(34)`、`TRANSACTION_STATE(22)`、必要なscheduler/reservation/capacity、kind 5/6/9 witness |
| `EV` | pre-materialized `EVIDENCE_CELL(32)`とstate/capacity、kind 7 witness |
| `OC` | `RESULT_CACHE(41)`、token `RESERVATION(23)`、state/retention/capacity、kind 10/11 witness |
| `ES` | `EVENT_SPOOL(50)`、`RETRY_SUMMARY(51)`、owner/reservation/capacity、kind 3/14/17 witness |
| `ER` / `ED` | `MANAGEMENT_LEDGER(52)`とEVENT_SPOOL/state/ordered-input companion、kind 15/16 witness |
| `RT` | `RETRY_SUMMARY(51)`とATTEMPT/state/capacity companion、kind 14 witness |
| `RV` | owner別`RESERVATION(23)`。単独markerは禁止 |
| `BS` | singleton `BEARER_STATE(60)`とkind 20 witness |
| cleanup/retention marker | `RETENTION_BASIS(61)`、`CLEANUP_PLAN(63)`、`ATTEMPT_REUSE_FENCE(64)`、kind 18 witness |
| durable invariant/counter fence | `INTERNAL_INVARIANT(01)`またはcanonical source record。family 5をaggregate health counterとして使わない |

`M4T`、`C3R`、MFDT、route/relay、Wi-Fi credential journalはこの変換表へ混入させない。
それらは各subsystemのAccepted namespace contractで分離し、Domain Runtime namespaceに
同居した場合はMIXED/CORRUPTである。

## 4. Writer contract

全semantic mutationは次の順を守る。

1. 同じREAD_WRITE transactionのpre-stateをexact-getし、D1/D2/D3の必要条件を検査する。
2. `docs/17`のoperation kind/phaseからclosed builderを1つ選ぶ。hook名から推測しない。
3. complete member setをkey unsigned-byte lexicographic順で構築し、
   old/new digest、prior head、capacity/reservation contributionをchecked計算する。
4. witness manifest chunk、ACTIVE header、semantic members、HEAD_INDEXを同じFULLへstageする。
5. commit OKだけをvolatile state/public resultへ反映する。
6. commit definite failureはrollbackし、volatile publish 0。
7. `COMMIT_UNKNOWN`はnamespaceをfenceする。同じmutable transactionをretryしない。
8. reopenでD3/D4がALL_OLD/ALL_NEW/MIXEDをfresh snapshotから分類する。

LAB key/value encode、dual-write、best-effort witness、count-only success、callback pointer
永続化はすべて禁止する。

## 5. Startup T2/T3/T6 closure

### 5.1 T2

T2はaggregate row countやT1 classifierをsuccess authorityにしない。D2 bounded scannerと
D3-S1..S12のclosed compositionを実行し、次をexactに得る。

- profile/binding/identity/current framing valid
- D3 slice dispositionが全てresolved
- witness member old/new、HEAD_INDEX、successor/retire chain valid
- primary/index/backlink/cardinality/resource contribution valid
- unresolved recovery itemのclosed list
- corruption/future/profile mismatchのprecedence確定

S1..S12のいずれかが未bind、未実装、deferred未解決なら
`storage_recovery_t0_t6_complete=0`のままpublication不可とする。

### 5.2 T3 / D4

T2が返したrecovery itemをlexicographic subject key順にexact 1件だけ選び、operation
kind 21のspecific FULL builderでconvergeする。1 commit後は必ずfresh READ_ONLY scanを
先頭から再実行する。durable scan cursor、同txn再試行、複数itemの巨大commitは作らない。

各witness groupの分類は次のclosed resultだけである。

- ALL_OLD: member exact old、CREATE absent、header/chunk absent
- ALL_NEW: member exact new、header/chunk/index/cross-row exact
- MIXED: missing/extra/third/partial/order/digest mismatch

ALL_OLDは同じlogical builderを再実行可能、ALL_NEWは再mutation 0、MIXEDは
`NINLIL_E_STORAGE_CORRUPT`でfenceする。Recovery itemが0になるまでT2→T3を繰り返す。

### 5.3 T6

T5後のfresh full scanからdurable health source multisetを再構成する。Source IDは
`complete key + source kind + stored epoch/reason`のcanonical tupleとし、同一sourceの
反復観測は1件、別sourceは同reasonでも別件とする。

Priority 1/2（unresolved storage/commit fence）が1件でもあればcreateを失敗させる。
Priority 3以降だけならDEGRADED publicationを許し、最小priorityをreasonへprojectする。
instance-local Storage/Bearer/entropy/provider failureをrestart後へcopyしない。

T6 outputは最低でもsource count、priority別count、最小reason、priority 1/2 countを
持ち、T7はpriority 1/2 count=0をexact要求する。

## 6. Fixed-memory and call-shape

- Scanner workspace 8192、Stage5-alone 8704、D3 aggregate ceilingはNormative freezeを
  超えない。大きなworkspaceはcreate arenaへ置き、Runtime live objectへ恒久埋込しない。
- key 255/value 4096を上限とし、VLA、再帰、全ID集合、unbounded visited setを使わない。
- 1 scan sessionは1 READ_ONLY txn、同時iterator最大1、cleanupは
  `iter_close -> rollback -> optional fence`。
- D4 writerは1 READ_WRITE txn、1 FULL、commit後live txn/iterator 0。
- public API callback、Bearer open/sendはT0–T6完了前exact 0。

## 7. Implementation order

1. 既存D3-S4候補を独立reviewしAccepted実装として統合する。
2. D3-S5を既存freeze/planから実装し、oracle/production bridgeを閉じる。
3. D3-S6..S12は各sliceをNormative freeze→independent oracle→productionの順で閉じる。
4. D3-S12 compositionをstartup T2へbindする。
5. D4 kind-21 planner/writer、fresh-rescan loopをT3へbindする。
6. T6 durable health source reconstructionをbindする。
7. public operation writerを§3の順で置換し、対応legacy key pathを削除する。
8. LAB export toolとexplicit cutover guideを実装する。
   POSIX SQLiteについては`tools/ninlil_lab_export.py`と
   `docs/lab-to-domain-cutover.md`で完了。全20 exact vector、offline authority
   lock、同一READ_ONLY transaction、no-overwrite、post-install verifyを自己試験する。
9. §8完了後、private readiness constantをreviewed changeで`1u`へpromoteし、
   feature-ON public Runtime testのDISABLED routingを同時に削除する。その後にだけ
   public Runtime Domain-ONをdefault candidateへ昇格し、旧LAB profileをrelease
   artifactから隔離する。

後段を前倒ししてpublicationだけgreenにしない。特にstep 4より前に
`storage_recovery_t0_t6_complete=1`を設定してはならない。

## 8. Acceptance matrix

### 8.1 Mandatory Host

- fresh Domain create → T0/T1a same RW、T1b、T5、T6、T7
- 16 SERVICE register/restart/explicit reattach、17th capacity rejection
- same service schema/descriptor/callback conflictとforged handle rejection
- submit/query/list/cancel/step/delivery/event resume/discardをDomain rowsだけでE2E
- operation kind 1..21のOK、definite failure、COMMIT_UNKNOWN ALL_OLD/ALL_NEW/MIXED
- process restart後にquota、transaction、scheduler、event、result、capacity、healthを復元
- Domain namespace内の各LAB key kindを1件ずつ混入しpublish/write/Bearer/callback 0
- format-1 LAB sourceはread-only exportだけ、source byte-for-byte不変
- explicit new namespace cutover後だけ新workをadmit
- `ninlil_v1_runtime_spine_test`をDomain-ONでgreen
- default-off LAB buildの既存behavior回帰green

### 8.2 Fault and portability

- T0..T7 stage fault matrix
- writerの全put ordinal、FULL、cleanup fault
- crash/power-cut scheduleのHost deterministic exhaustive set
- ASan/UBSan、pointer-pair、strict C11、GCC/Clang、Linux/macOS
- tests-OFF install/subproject consumer、exact symbol inventory
- ESP-IDF compile/map/DRAM/stack budget。物理power-cut HILは別evidenceとして残してよいが、
  software completionと混同しない。

## 9. Promotion rule

次の全てがgreenになるまでADR-0022の状態は
`SPEC_ACCEPTED (design only) — implementation incomplete`のまま、
Domain-ON public publicationはrelease claimに含めない。

- D3-S1..S12 implementation accepted
- D4 convergence accepted
- T2/T3/T6が実authorityへbind
- §3 legacy writer 0、Domain writer full coverage
- §8 Host/portability matrix green
- migration/export artifact/tool green
- P0/P1=0の独立review
