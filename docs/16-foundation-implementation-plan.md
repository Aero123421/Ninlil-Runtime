# 16. Foundation Implementation Plan

状態: Informative execution plan
対象: Foundation M1aを実装する最初の連続PR

## 目的

本章は、[08. Foundation Release](08-foundation-release.md)を小さく検証可能な変更へ分けます。Public contractの正本は12〜14章であり、本章は要件を変更しません。

実装中に仕様の穴を見つけた場合、codeだけで判断を固定せず、先に該当するnormative文書、test vector、ADRを更新します。

## 実装開始時の前提

- M0 decisionとFable review dispositionが記録済み。
- 12章のC ABI、13章のreducer、14章のport/vectorに重大な矛盾がない。
- M1aは`TEST` environment、`CONTROLLER` / `ENDPOINT`、single targetだけ。
- KGuard、Legacy LinkOS、radio、ESP-IDFをportable Coreへimportしない。
- `ADMITTED_SCHEDULED`、counter-offer、selector、group、supersedeを実装済みと表示しない。

## PRの順序

### PR 1: Public ABI and generated manifest

成果物:

- `include/ninlil/*.h`
- C11/C++17 compile/link smoke
- enum value、`sizeof`、`offsetof`のgenerated ABI manifest
- public output initialization、nullability、small/future `struct_size` test
- machine-readable reason code registry
- reason registryの全codeとOperator Model projection contractの機械検査
- 12〜14章で「mirror」と明記した規範表のgenerated comparison（現時点ではhook registry。今後追加したexplicit mirrorも含む）
- 14章の全vector ID inventoryとmandatory suite / PR gate参照の機械検査（重複、欠番、未定義range、孤立vectorを禁止。これは表mirrorとは別検査）
- `requirements-traceability.yaml`のskeletonと12章requirement mapping開始

Gate:

- 12章の宣言とgenerated headerの差分が0。
- explicit規範表mirror、vector inventory/reference、reason registry、Operator Model linkの差分・欠損が0。
- unsupported機能が規範どおり拒否される。
- implementation bodyが未完成でも、成功を返すstubを作らない。

### PR 2: Deterministic reducer model

成果物:

- Submission、Transaction、Target、Delivery、Event spoolのpure reducer
- durable scheduler owner/cursor、stable input ordering、same-time priority、targeted management catch-upのpure model
- reason/outcome/deadline projection
- resource ledgerのpure accountingとmetrics/health projection
- in-memory model store
- 13章のmandatory vector

Gate:

- reducerがclock、filesystem、thread、randomへ直接依存しない。
- same state + same ordered inputからbyte-identical public snapshotを得る。
- terminal reversal、EventFact silent discard、attempt counter rollbackが0。

### PR 3: Port contracts and canonical fixtures

成果物:

- bounded allocator/execution/clock/entropy adapters
- in-memory storage conformance double
- typed simulated bearerとvirtual Tx Gate
- TEST origin authorization provider
- in-memory store上の`runtime_step` orchestration（recovery barrier、Bearer state、ring/ingress lane、budget、next wake、first error）
- canonical C1/E1、entropy、grant vector
- 12〜14章と07章invariantのstable requirement ID / test / profile / gate mappingを完成

Gate:

- 14章のcanonical bytes/digestへ一致。
- provider-specific statusとpublic API statusのmappingを全分岐test。
- caller buffer mutation後もaccepted bearer copyが不変。
- `requirements-traceability.yaml`にM1a normative requirementの未対応・重複・孤立test IDが0。

### PR 4: Restart-safe POSIX storage

成果物:

- SQLite storage port
- schema/migration marker
- namespace binding、4 durable counter/cursor、single-writer lease
- durable service registryとRuntime recreate時のservice reattach
- 11-kind resource ledger、capacity epoch、retention basis/cleanup
- origin transaction query/listとstable pagination
- admission、outbox、inbox、result cache、event spool、auditのatomic group
- commit-unknown recovery
- logical entry/byte accounting

Gate:

- in-memory modelと同じoperation trace。
- namespace/service/ledger/query/scheduler cursorがrestart前後で14章のNS/SV/CAP/RET/QRY/SCH vectorへ一致する。
- 全named commit/crash boundaryでall-or-none。
- partial group、unknown schema、corruptionをsuccessへfallbackしない。

PR 4の実装前に[17章](17-foundation-domain-store.md)のD0〜D3を独立境界として完了します。D0はNormative inventory、D1はpure codec/catalog、D2はbounded read-only scanner、D3はcounter/capacity/index/health相互validationです。**D3-S0 Normative architecture freeze（[17章 §18](17-foundation-domain-store.md)）と D3-S1a closed-mode/context freeze（[17章 §18.12](17-foundation-domain-store.md)）は docs only で完了済み; D3-S1..S12 implementation は pending。** D3-S0 / D3-S1a を D3 complete / Stage 5 complete に置換しません。D4 operation別convergence以降をSQLite writerと接続し、bootstrap-only orchestrationやempty scanをPR 4完了の代用にしません。

### PR 5: Reliable Command path

成果物:

- Controller admission/outbox/attempt
- Endpoint delivery/application token/result cache
- Receipt/Disposition
- deadline/evidence grace/late evidence
- cancel/reconcile
- generic Reliable Command example

Gate:

- APPLIED commit前にSATISFIEDを出さない。
- callback前、effect後、cache前後のcrash matrix。
- duplicate dispatch時のsemantic effectがservice apply contract内。

### PR 6: Durable Event path

成果物:

- TEST grantによるorigin admission
- no-deadline event spool
- 8-attempt retry cycle、park、fresh epoch/manual resume
- controller persistent event dedup
- audited discard
- generic Durable Event example

Gate:

- controller commit前にDURABLY_RECORDEDを返さない。
- retry exhaustion、restart、grant expiryでadmitted eventを捨てない。
- discard audit commit前のspool releaseが0。

### PR 7: Simulator, fault matrix and release evidence

成果物:

- strict fault-script loader
- deterministic harness/trace
- fixed regression scenarios、seed replay、crash sweep
- ASan/UBSan、fuzz smoke、docs/example smoke
- limitations、porting note、compatibility matrix

Gate:

- PR seed setとnightly seed setが07/14章どおり通る。
- 同一seed/scriptのtrace digestとfinal snapshotが再現する。
- M1aで証明していないradio/security/compliance/field SLOをrelease noteへ明記する。

## Mandatory contractの担当PR

この表は実装漏れを防ぐcoverage ownerです。複数PRに跨る項目は、前半PRがmodel/interface、後半PRがdurability/integrationを担当します。PR 7で14章`M1a mandatory suites`の各requirement setをこの表と実testへ逆引きし、ownerなしを0件にします。

| Contract area | Primary PR | Completion evidence |
| --- | ---: | --- |
| public ABI、reason registry、Operator projection、unsupported boundary | 1 | generated ABI/registry、C11/C++17、RF/RZ/U/SR/RL |
| reducer、scheduler owner/cursor、same-time order、management linearization | 2 | M1A state vectors、SCH/SC/MG、pure replay |
| Port status/ownership、runtime step、budget/clock/wake、metrics/health | 3 | FULL/MB/SH/BH、BS/P/TG、B/W/MT/HL、in-memory trace |
| namespace/create/destroy、service registry/reattach、resource ledger、retention、query/list、SQLite recovery | 4 | NS/CR/DR/SV/CAP/RET/QRY/QPX、commit-unknown matrix |
| Command、callback/token、Receipt/Disposition/cancel/reconcile | 5 | C1、F/CB/DV/R/O2、Command M1A and crash vectors |
| Event admission/custody/retry/park/availability/resume/discard | 6 | E1〜E4、G/AQ/AV/M/A1、Event M1A and crash vectors |
| closed hook registry、full conformance inventory、fault/replay/release evidence | 7 | HC/all named hooks、全mandatory suite、seed/fuzz/sanitizer/docs gate |

PRを分割・統合する場合もcontract area owner、test ID、durable boundaryを先に更新し、後続PRへ暗黙移送しません。

## Experimental KGuard validationへの入口

PR 1〜7とM1a exit gate完了後に開始できるのは、software-only `TEST` laneです。

- PC上のControllerとsimulated bearerまたはoptional POSIX loopback Endpoint
- KGuard Display adapterのsingle-target DesiredStateCommand / APPLIED
- KGuard Leak adapterのEventFact / DURABLY_RECORDED
- Ninlil public APIのみを利用し、USB実機・SX1262・radio TXを使わない

PC + USB Cell Agent + Display + Leakのphysical `LAB` laneはFoundationの実装順ではなく、09章どおりM3のESP-IDF/Cell Agent最小sliceとM5のLAB Tx Gate/radio subset完了後に開始します。Legacy codeをCoreへ移植して短絡せず、実機で見つかったcontract変更は仕様とgeneric conformance testへ戻します。

## 実装者が独自決定してはいけない項目

- enum値、struct field順、pointer/token ownership
- idempotency scopeとcanonical encoding
- commit-before-effectの境界
- same-time input priority
- deadlineとlate evidenceの判定
- retry budget、park、resume、discard
- provider statusからpublic statusへのmapping
- resourceの単位、予約、解放順
- unsupported featureのfallback

未定が見つかった場合の成果は「推測したcode」ではなく「仕様差分 + test vector + 判断理由」です。
