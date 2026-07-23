# B1: public Runtime body 実装トランチ計画（素案）

状態: **draft rev6**（Sol high r5レビュー反映済み; r5 P0=1 P1=1 P2=1 全件対応）
作成: 2026-07-21 / orchestrator: Fable
改訂: 2026-07-22 rev6（r5 NO-GO所見 P0=1 P1=1 P2=1 全件反映; r1〜r4引継ぎ）
入力: `docs/work/2026-07-21-b1-contract-audit.md`（B1事前監査 rev6）, `docs/work/2026-07-21-master-plan.md` §2 Phase B #5
様式参照: `docs/work/2026-07-21-d3s3-r27-bridge-recovery-plan.md`

## 0. 完成条件（master plan §0再掲）

stub / TODO / 未接続candidate / compile-only を完成扱いしない。14 APIすべてがdocs/12正本semanticどおりに動作し、durable pathがcrash/restartで収束することを証拠付きで示す。KGuard固有語彙をportable Coreへ入れない。

**CI gate（master plan §0準拠）**: 各段階のmerge前提は以下すべて:
- Configure + build (Linux/macOS, strict warnings)
- full ctest (`--no-tests=error` 必須。該当テスト0件での成功を禁止)
- ASan + UBSan buildでのfull ctest
- ESP-IDF target build (cross-compile, ctest対象外でもbuild成功必須)
- public consumer link test: 外部consumerが`ninlil` libraryをcompile+link+実行し14 symbolすべてを解決できること

## 1. 前提依存

| 依存 | 内容 | 状態 |
|------|------|------|
| A4完了 | Stage5 D3 bind + D4 commit-unknown convergence。B1-aのStage 5 recovery scanはA4のD3 bind/D4 convergenceが完了したdomain storeの上で動作する | **未完了**（master plan §2 Phase A #4） |
| D3-S3回収 (A1) | domain_store_d3s3のcross-row閉積。A1-A4のStage 5 recovery scanが依存。B1-cのlive operation/read-write seamとは独立（r2 P0-3反映） | 進行中 |
| D3-S4 witness (A2) | §18.15 witness実装。B1-cのrecovery work/witness chainが依存 | 未着手 |
| A3完了 | D3 validation + namespace integrity。B1-cのlive operation/read-write seamがA3のvalidation完了domain上で動作する | **未完了** |
| L2a/L2b1 | runtime_store_bootstrap/codec。B1-aが直接消費 | **済**（master plan §1） |
| runtime_store_stage5_seam | Stage 5 seam。B1-aが直接消費 | **済**（候補） |
| CMake実体化 | public `ninlil` targetのINTERFACE→実体化（master plan §2 Phase B #5）。B1-aの受入前提 | **未完了** |

**A4 gate（rev2修正, P0-2反映）**: B1-aの受入（acceptance）はA4完了を無条件gateとする。Stage 5 recovery未完了ではBearer openへ進めない（docs/12:1170）。コード準備（Stage 1-4, 6-9のbody記述）はA4前に可能だが、B1-a受入テストのpassおよび全後続段階（B1-b〜B1-g）の開始はA4完了後に限定する。

## 2. 段階分割

監査（`2026-07-21-b1-contract-audit.md` §6）のリスク上位5論点をB1-a〜B1-eへ先頭配置、残APIをB1-fへまとめ、cross-API E2EをB1-gとする。

---

### B1-a: runtime_create / runtime_destroy body + library実体化（Risk 1）

**Normative根拠**:
- docs/12:1160-1207（Stage 1-9 exact order, failure mapping）
- docs/12:1233-1278（Private Runtime Store v1, L2a/L2b境界）
- docs/12:1172（Stage 7 CLOCK_BASELINE比較・FULL更新）
- docs/12:2413-2421（destroy consume/lifecycle, operation kind 19）
- docs/04:384-394（crash recovery）
- 監査 §5: U1, U2, U3, G1

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `CMakeLists.txt` | public `ninlil` targetをINTERFACE→実体化（static or shared library）。install/export rule追加。外部consumer用link interface設定 |
| `tests/consumer/` 新規 | 外部consumer link test: 14 symbolのcompile+link+実行を検証する最小test |
| `src/runtime/` 新規または既存 | runtime_create body: Stage 1-9 orchestration。L2a bootstrap codec (`src/model/runtime_store_bootstrap.c`) とstage5 seam (`src/runtime/runtime_store_stage5_seam.c`) を接続 |
| `src/runtime/` 新規または既存 | runtime_destroy body: DESTROYING fence → active token group recovery (kind 19) → bearer.close → storage.close → deallocate |
| `src/model/runtime_lifecycle_model.c/.h` | health 8-slot projectionのStage 9 publish gate接続（durable marker再構成はA4依存） |
| `tests/runtime/` | 負系/受入テスト新規 |

**禁止事項**:
- public ABI (`include/ninlil/*.h`) 変更禁止
- docs/17変更禁止
- Stage 5のdomain recovery scan（family 5/6）をA4完了前に完成扱いしない
- stub/TODO/compile-onlyの完成扱い禁止

**CLOCK_BASELINE（rev2修正, P0-5反映）**: Stage 7はCLOCK_BASELINEとの比較・FULL更新を含むproduction pathを実装する（docs/12:1172）。Semanticは既に固定済みであり、A4またはB1-aのどちらが実装してもよいが、B1-a受入前にproduction path接続が完了していること。A4/D1以降へのdeferは認めない。

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| U1 (L2b bounded memory region設計) | **docs先行freeze**: B1-a実装開始前にFableがL2b memory region設計をdocs/workへ固定。Sol highレビューで確定 | B1-a着手前 |
| U2 (family 5/6未生成) | **docs先行freeze**: A4完了までStage 5はfamily 5/6を生成しないことをdocs/workへ明記。B1-aはempty namespace bootstrap + profile binding + counter/capacity loadのみ | B1-a着手前 |
| U3 (CLOCK_BASELINE 17章) | **rev2修正**: Stage 7 CLOCK_BASELINE production compare/updateはB1-aスコープ内。17章family 6 subtype 62のsemanticはdocs/12:1172で固定済み。実装配置はdocs/workで決定可。normative semanticの追加・変更はcanonical doc/vectorへfreeze | B1-a実装内 |
| G1 (destroy token group module) | **Solレビュー確定**: destroy pathのoperation kind 19実装場所（runtime_lifecycle_model内 or 新規module）をB1-a計画レビューでSol highが確定。注: 実装設計事項でありpublic contract不足ではない（P2-2反映） | B1-aレビュー |

**負系/受入試験**:
1. Stage 1 validation: 全invalid config/platform combinationでexact API status（12:1156-1157のclosed precedence）
2. Stage 4 storage open: BUSY→WOULD_BLOCK, NO_SPACE→CAPACITY_EXHAUSTED, IO→STORAGE, CORRUPT→STORAGE_CORRUPT, COMMIT_UNKNOWN→STORAGE_COMMIT_UNKNOWN, UNSUPPORTED_SCHEMA→UNSUPPORTED
3. Stage 6 bearer open: WOULD_BLOCK/UNAVAILABLE→WOULD_BLOCK, DENIED→UNSUPPORTED, EMPTY/LOST_UNKNOWN/CORRUPT→DEGRADED
4. Stage 7 clock: CLOCK_BASELINE比較・FULL更新のproduction path検証。UNCERTAIN→CLOCK_UNCERTAIN, permanent/zero epoch/regression→DEGRADED
5. Stage 8 entropy: 4-call exhaustion→ENTROPY, all-zero candidate→次call
6. Empty namespace: 17-record initial bootstrap 1 FULL commit, commit unknown→fence
7. Existing namespace: profile exact match→継続, 1 field mismatch→UNSUPPORTED
8. Destroy: active token group→1 FULL commit EXPIRED/RECOVERY_REQUIRED, commit failure→handle still consumed
9. Destroy: no active token→storage write 0, OK
10. Restart: same namespace reopen→profile/counter/capacity load, partial→CORRUPT
11. Identity forward rotation: 旧identity→新identityへrotation成功、regressive epoch→CONFLICT（P1-3反映）
12. Recreate後のservice reattach: 旧callback pointer非比較、unattached serviceのdispatch/callback抑止（P1-3反映）
13. Consumer link test: 外部consumerが14 symbolをcompile+link+実行（P0-1反映）

**完了コマンド**: `ctest --test-dir build -R "runtime_create|runtime_destroy|consumer_link" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean, consumer link test pass

---

### B1-b: service_register + submit admission body（Risk 4）

**Normative根拠**:
- docs/12:1280-1390（Descriptor validation, role×family matrix, durable semantic registry）
- docs/12:1560-1654（Submission ABI, admission exact order, idempotency, result matrix）
- docs/12:1032（全family新規admission exact order 11段階）
- docs/12:1344-1366（Admission quota semantics）
- docs/14:1970（canonical-submission-v1 exact byte layout）（P0-9反映）
- docs/04:98-108（Idempotency）, 04:351-371（Atomic boundary）
- 監査 §5: G4

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `src/model/submission_preflight.c/.h` | syntax/schema/content digest validationのruntime body接続 |
| `src/model/submission_admission.c/.h` | admission control, idempotency lookup (key mapping + event mapping二重), quota, provider call orchestration |
| `src/model/resource_ledger.c/.h` | admission reservation (複数kind昇順reserve/逆順release) |
| `src/runtime/` 新規または既存 | service_register body: descriptor validation → FULL commit → handle publish。Exact再登録/conflict |
| `src/runtime/` 新規または既存 | submit body: preflight → idempotency → clock sample → counter headroom → provider → quota → reservation → transaction ID draw → 1 FULL admission commit |
| `tests/runtime/` | 負系/受入テスト新規 |

**禁止事項**:
- public ABI変更禁止
- canonical submission digestのbyte layoutはdocs/14:1970が正本。推測で変更しない（P0-9反映）
- EventFactのorigin authorization provider callをstubで完成扱いしない
- stub/TODO/compile-onlyの完成扱い禁止

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| G4 (canonical submission digest実装場所) | **rev2修正**: exact byte layoutはdocs/14:1970に存在する（P0-9反映）。実装moduleの配置はdocs/workで決定可。normative semanticの追加・変更はcanonical doc/vectorへfreezeし、レビュー判断だけで確定しない | B1-bレビュー |

**負系/受入試験**:
1. service_register: reserved family→UNSUPPORTED, wrong direction/authority→UNSUPPORTED, callback shape mismatch→INVALID_ARGUMENT
2. service_register: exact再登録→same handle/no write, contract mismatch→CONFLICT
3. service_register: receiver handleからsubmit→`NINLIL_OK + REJECTED + UNSUPPORTED_DIRECTION`
4. service_register: identity forward rotation後の再登録、regressive epoch conflict→CONFLICT（P1-3反映）
5. service_register: recreate後のservice reattach、旧callback pointer非比較、unattached serviceのdispatch/callback抑止（P1-3反映）
6. submit: target_count 0/2→REJECTED/TARGET_COUNT_UNSUPPORTED
7. submit: same key/same digest→ALREADY_ADMITTED, same key/different digest→IDEMPOTENCY_CONFLICT
8. submit: EventFact triple (event_id/digest/key) conflict全pattern
9. submit: quota exhaustion (inflight/rate/byte) → REJECTED + exact reason/guidance/delay
10. submit: admission FULL commit→transaction+target+descriptor ref+reservation+idempotency+outbox atomic
11. submit: commit unknown→STORAGE_COMMIT_UNKNOWN, caller ownership
12. submit: result全field matrix (12:1641-1648) exact match
13. submit: transaction/scheduler両counter headroom不足→REJECTED + exact reason（P1-4反映）
14. submit: clock failure→CLOCK_UNCERTAIN, 後続call（provider/quota/reservation/entropy/commit）すべて抑止（P1-4反映）
15. submit: Origin Authorization DENY/TEMPORARY/PERMANENT/poison→各exact result + 後続call（quota/reservation/entropy/commit）抑止（P1-4反映）
16. submit: entropy 4-draw exhaustion→ENTROPY + **reserve済みkindを逆順release**（正本順序でreservation後にentropy drawするため）+ 後続call（commit）抑止（r3 P1-4反映: docs/12:1032の順序 reservation→ID draw）
17. submit: idempotency hit (ALREADY_ADMITTED)→後続call（provider/quota/reservation/entropy/commit）抑止、既存transaction返却（r2 P1-4反映）
18. submit: idempotency conflict (IDEMPOTENCY_CONFLICT)→後続call（provider/quota/reservation/entropy/commit）抑止、caller ownership（r2 P1-4反映）
19. submit: counter exhaustion→後続call（provider/quota/reservation/entropy/commit）抑止（r2 P1-4反映）
20. submit: provider deny/failure→後続call（quota/reservation/entropy/commit）抑止（r2 P1-4反映）
21. submit: quota rejection→後続call（reservation/entropy/commit）抑止。providerは既にcall済み（正本順序: preflight→idempotency→clock→counter→provider→quota→reservation→ID draw→commit）（r2 P1-4反映）
22. submit: reservation failure→reserve済みkindを逆順release、後続call（entropy/commit）抑止（r2 P1-4反映）
23. submit: Storage failure (admission commit)→caller ownership、STORAGE_COMMIT_UNKNOWN（r2 P1-4反映）
24. submit: 全Storage status mapping (BUSY→WOULD_BLOCK / NO_SPACE→CAPACITY_EXHAUSTED / IO→STORAGE / CORRUPT→STORAGE_CORRUPT / COMMIT_UNKNOWN→STORAGE_COMMIT_UNKNOWN / UNSUPPORTED_SCHEMA→UNSUPPORTED)（P1-4反映）
25. submit: canonical golden vector: docs/14:1970のexact layoutでdigest計算のgolden test（P1-4反映）
26. submit: exact no-call trace総合: 各failure pointで後続stepが呼ばれないことをcall traceで検証（r2 P1-4反映）

**完了コマンド**: `ctest --test-dir build -R "service_register|submit_admission" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean

**依存**: B1-a完了（Runtime handle存在）。A4完了（idempotency mappingのdurable lookupがdomain store上で行われる場合）

---

### B1-c: runtime_step orchestration body（Risk 2）

**Normative根拠**:
- docs/12:2077-2164（Step scheduler and clock contract, ring/ingress lane, micro-operation）
- docs/12:2110-2148（Work kind closed set 22種, tie-break）
- docs/12:2150-2162（Cursor commit placement）
- docs/12:2221-2254（Step budget accounting）
- docs/12:836-883（Bearer ownership, availability epoch）
- docs/04:12-21（Foundation実行モデル, single-owner event loop）
- 監査 §5: C2, G6

**rev3設計修正（r2 P0-3反映）**: D3-S1/S2/S3はStage 5 namespace recovery scannerであり（`domain_store_d3s1.h:4`参照）、scheduler micro-operation分類ではない。B1-cの編集資産に含めない。
- **A1-A4側のrecovery bind**: d3s1/d3s2/d3s3はA1-A4が完了したdomain storeのStage 5 recovery scanに使用。B1-cはこれらを編集・消費しない
- **B1-cのlive operation/read-write seam**: runtime_stepのring/ingress laneで実行するlive micro-operationは、scheduler_candidate pure modelとdomain storeのlive read-write seamを直接使用。d3s phase分割とは完全に独立。B1-cの編集範囲にd3s1/d3s2/d3s3を含まない

**rev2設計修正（P0-4反映）**: B1はpublic `ninlil_bearer_ops_t`のtyped messageを直接使用する（`platform.h:207`）。NCL1はU4 private control envelopeであり（`ncl1_codec.h:4`）、B1スコープから明示的に除外する。control_session/logical_session（`src/transport/`）もB1スコープ外。これらは後続Bearer provider/U4統合トランチへ送る。

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `src/model/scheduler_candidate.c/.h` | ready candidate selection/orderingのruntime body接続。22 work kind tie-break |
| `src/model/deadline_projection.c/.h` | timer due判定（step-entry sample基準） |
| `src/model/desired_deadline_transition.c/.h` | Command state transition (expiry, evidence close) |
| `src/model/required_receipt_transition.c/.h` | Receipt/Disposition reduce |
| `src/runtime/storage_canonical_plan.c/.h` | canonical plan (begin→final view) のstep commit接続 |
| `src/runtime/domain_store_scanner.c/.h` | ingress copy/reducer candidate scan |
| `src/runtime/` 新規または既存 | runtime_step body: Stage 1-6 (clock→recovery→bearer state→cut→ring/ingress→health) |
| `tests/runtime/` | 負系/受入テスト新規 |

**禁止事項**:
- public ABI変更禁止
- d3s1/d3s2/d3s3をB1-cの編集資産に含めない。recovery work kindとしての消費もしない（r2 P0-3反映）
- NCL1 codec / control_session / logical_sessionをB1内で接続しない（P0-4反映）
- Bearer messageは`ninlil_bearer_ops_t` typed messageのみ使用
- stub/TODO/compile-onlyの完成扱い禁止

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| C2 (d3s phase vs ring lane対応) | **解消済み（r2 P0-3反映）**: D3-S群はrecovery scannerでありring laneとは無関係。B1-cの編集資産から完全除外。live operationは独立seam | 解消済み |
| G6 (src/transport/接続) | **rev2修正（P0-4反映）**: control_session/logical_sessionはB1スコープ外と確定。後続Bearer provider/U4統合トランチへ送る | 解消済み |

**負系/受入試験（closed coverage表, P0-8反映）**:

| # | 試験項目 | 検証内容 | 典拠 |
|---|----------|----------|------|
| 1 | Step clock failure | first errorで全Port/callback 0, more_work=0 | 12:2081 |
| 2 | Step budget 0 | counter 0, pending workあればmore_work=1 | 12:2249 |
| 3 | Ring/ingress lane交互 | continuous ingressがring ownerをstarveしない | 12:2085-2088 |
| 4 | Cursor | 1 micro-opで最大1回update, COMMIT_UNKNOWN→cursor推測しない | 12:2150-2162 |
| 5 | Bearer state | strictly larger epoch→FULL commit, same epoch→write 0, different flag→contract failure | 12:836-883 |
| 6 | Ingress | receive_next EMPTY→lane close, DENIED→first error step停止 | 12:2085 |
| 7 | Budget preflight | on_deliveryはcallback 1 + state transitions 2, DEFER→2つ目返却 | 12:2221-2254 |
| 8 | Work kind tie-break | logical time昇順→semantic priority→work class→input sequence→target→kind→tie ID/generation | 12:2110-2148 |
| 9 | Send observation前crash | same attempt再送可, observation後: 再送しない | 04:386-394 |
| 10 | Health projection | 8-slot closed multiset, lowest-number non-zero→DEGRADED/reason | 12:2280-2314 |
| 11 | Recovery barrier | recovery work完了までlive micro-op実行しない | 12:2121 |
| 12 | Stage 4 cut | scheduler cut後の新規candidateは次stepへ持ち越し | 12:2121 |
| 13 | Ownerあたり1 micro-op | 同一ownerが1 stepで2 micro-op実行しない | 12:2121 |
| 14 | 全22 work kind実体接続（r2 P0-8反映: per-kind closed coverage表） | 下表参照 | 12:2110-2148 |

**22 work kind per-kind closed coverage表（r2 P0-8反映）**:

各kindごとにproduction entry / budget消費 / Port or callback / FULL commit or hook pair / cursor update / crash replayの6軸を検証する。全行passなしでB1-c完了としない。

| kind# | work kind名 | production entry | budget | Port/callback | FULL commit/hook | cursor | crash replay |
|-------|-------------|-----------------|--------|---------------|-----------------|--------|--------------|
| 1 | DURABLE_REDUCER_INPUT | ingress reducer | 1 micro-op | なし | reducer FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same reduce result |
| 2 | AVAILABILITY_CONSUME | availability epoch change | 1 micro-op | なし | availability FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same consume |
| 3 | COMMAND_EFFECT_DEADLINE | timer due (step-entry sample) | 1 micro-op | なし | deadline transition FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same transition |
| 4 | COMMAND_EVIDENCE_CLOSE | timer due (step-entry sample) | 1 micro-op | なし | evidence close FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same close |
| 5 | ATTEMPT_RECEIPT_TIMEOUT | timer due (step-entry sample) | 1 micro-op | なし | receipt timeout FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same timeout |
| 6 | INTERNAL_RETRY_DUE | timer due (step-entry sample) | 1 micro-op | なし | retry state FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same retry |
| 7 | DELIVERY_TOKEN_TIMEOUT | timer due (step-entry sample) | 1 micro-op | なし | token EXPIRED FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same expiry |
| 8 | RECONCILE_DUE | timer due (step-entry sample) | 1 micro-op | なし | reconcile claim FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same claim |
| 9 | DELIVERY_CALLBACK | ring owner dispatch | 1 micro-op (callback 1 + transitions 2) | on_delivery callback | DELIVERY_STARTED pre-commit (cursor含む); COMPLETE→result commit; **DEFER→追加write 0**（docs/12:2242） | cursorはDELIVERY_STARTED success commit内に配置（callback前）。DEFERは追加write 0だがcursorはDELIVERY_STARTEDに含まれ済み（r4 P0-8反映: docs/12:2152） | pre-commit後crash→RECOVERY_REQUIRED |
| 10 | RECONCILE_CALLBACK | ring owner dispatch | 1 micro-op (callback 1 + **transitions 1**) | on_reconcile callback | claim commit + action commit (cursor含む) | cursorはreconcile **result commit**内に配置（r5 P0-8反映: docs/12:2159正本。claim commitではない） | claim後crash→exact 1回action |
| 11 | APPLICATION_ATTEMPT_PREPARE | ring owner | 1 micro-op | **Entropy Port**（docs/12:520: attempt nonce draw） | attempt prepare FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same prepare |
| 12 | APPLICATION_SEND | ring owner | 1 micro-op | **fresh Clock sample + TxGate transition + Bearer send Port**（docs/12:520, 2164） | send observation FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 13 | CANCEL_ATTEMPT_PREPARE | ring owner | 1 micro-op | **Entropy Port**（docs/12:520: cancel attempt nonce draw） | cancel prepare FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same prepare |
| 14 | CANCEL_REQUEST_SEND | ring owner | 1 micro-op | **fresh Clock sample + TxGate transition + Bearer send Port**（docs/12:520, 2164） | cancel send FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 15 | RECEIPT_REVERSE_SEND | ring owner | 1 micro-op | Bearer send Port | reverse send FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 16 | DISPOSITION_REVERSE_SEND | ring owner | 1 micro-op | Bearer send Port | reverse send FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 17 | CUSTODY_ACCEPTED_REVERSE_SEND | ring owner | 1 micro-op | Bearer send Port | reverse send FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 18 | CANCEL_RESULT_REVERSE_SEND | ring owner | 1 micro-op | Bearer send Port | reverse send FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | observation前→再送可、後→再送しない |
| 19 | RETENTION_BASIS_UPDATE | ring owner | 1 micro-op | なし | retention basis FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same basis |
| 20 | TERMINAL_RETENTION_CLEANUP | ring owner | 1 micro-op | なし | cleanup FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same cleanup |
| 21 | RESULT_TOKEN_RETENTION_CLEANUP | ring owner | 1 micro-op | なし | cleanup FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same cleanup |
| 22 | OBSERVATION_RETENTION_CLEANUP | ring owner | 1 micro-op | なし | cleanup FULL commit | micro-opのFULL commit内（docs/12:2150-2162） | replay→same cleanup |

注: 上表はdocs/12:2110-2148, docs/12:2150-2162 (cursor: 2152, 2159), docs/12:2242, docs/12:520, docs/12:2164, docs/13 (work kind semantic) に基づくclosed specificationである。Port/callback列は各kindが消費するplatform Port（Entropy/Clock/Bearer/TxGate）を明示。cursor列はexact commit placementを固定（multi-commit kind: DELIVERY_CALLBACKはDELIVERY_STARTED commit内、RECONCILE_CALLBACKはresult commit内）。実装が上表と不一致の場合は実装を修正する。
| 15 | TxGate/Bearer | TxGate state machineとBearer send/receiveのclosed interaction | 12:2121 |
| 16 | Receive loan release | ingress receive loanのexact release timing | 12:2121 |
| 17 | Reverse send | reverse direction sendのmicro-op実体 | 12:2121 |
| 18 | Retention | retention cleanup work kindの実体 | 12:2121 |
| 19 | Cursor同時commit | cursor updateとmicro-op commitのatomicity | 12:2150-2162 |
| 20 | Crash replay | crash後のrecovery work replayがexact same outcomeへ収束 | 12:2164 |

**完了コマンド**: `ctest --test-dir build -R "runtime_step" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean, 22 work kind closed coverage表全行pass

**依存**: B1-a完了, B1-b完了（step対象のtransaction/serviceが存在）。A1完了（d3s3 cross-row, recovery scan前提）。A2完了（witness chain, recovery work）。**A3完了（D3 validation, r2 P0-3反映）**。**A4完了（D4 convergence, r2 P0-3反映）**。注: d3s1/d3s2/d3s3はB1-cの編集資産ではなく、A1-A4のrecovery scanが使用。B1-cのlive operationは独立seam

---

### B1-d: delivery_complete + callback lifecycle body（Risk 3）

**Normative根拠**:
- docs/12:1400-1558（Delivery/Application result, callback contract, deferred completion）
- docs/12:1520-1543（delivery_complete validation/status precedence ordered table）
- docs/12:1475-1485（token lifecycle, DELIVERY_STARTED pre-commit, FATAL/contract recovery）
- docs/12:2280-2314（health 8-slot closed multiset）
- docs/04:259-268（Exactly-once境界, DELIVERY_STARTED durable記録）
- 監査 §5: U6, G5

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `src/model/required_receipt_transition.c/.h` | evidence stage validation, result cache binding |
| `src/model/resource_ledger.c/.h` | deferred token slot reserve/release |
| `src/model/domain_store_codec.c/.h` | result cache record encode/decode |
| `src/runtime/` 新規または既存 | delivery_complete body: 13段階ordered validation → clock → evidence copy → FULL commit |
| `src/runtime/` 新規または既存 | callback dispatch: DELIVERY_STARTED pre-commit → token allocation → on_delivery/on_reconcile → result commit |
| `src/model/runtime_lifecycle_model.c/.h` | health 8-slot projection（callback contract/application failure fence） |
| `tests/runtime/` | 負系/受入テスト新規 |

**禁止事項**:
- public ABI変更禁止
- role固有hook pair名 (`controller.before_*` / `endpoint.before_*`) のexact実装seamを推測しない
- callback FATAL/contract violationのrecoveryをstubで完成扱いしない
- stub/TODO/compile-onlyの完成扱い禁止

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| U6 (delivery_complete hook pair seam) | **Solレビュー確定**: role固有hook pairのsrc/runtime/内対応moduleをB1-d計画レビューで確定。注: 実装設計事項でありpublic contract不足ではない（P2-2反映） | B1-dレビュー |
| G5 (health 8-slot projection実装) | **Solレビュー確定**: runtime_lifecycle_model内 or 別moduleをB1-d計画レビューで確定。注: 実装設計事項でありpublic contract不足ではない（P2-2反映） | B1-dレビュー |

**負系/受入試験（P1-5反映: 詳細化）**:
1. delivery_complete ordered table 13段階を個別test case化:
   - 1a. NULL runtime/token/result→INVALID_ARGUMENT
   - 1b. bad ABI header→ABI_MISMATCH
   - 1c. wrong thread→WRONG_THREAD
   - 1d. callback re-entry→REENTRANT
   - 1e. invalid token field (context 0/epoch 0/generation 0)→INVALID_ARGUMENT (active token不変)
   - 1f. token NOT_FOUND→NOT_FOUND
   - 1g. token INVALID_STATE (already consumed/expired)→INVALID_STATE
   - 1h. clock uncertain→CLOCK_UNCERTAIN
   - 1i. runtime DEGRADED→DEGRADED
   - 1j. completion timeout: expiry境界 `==` はcompletion優先（有効、NINLIL_OK）、`>` のみtimeout→INVALID_STATE + EXPIRED tombstone（r2 P1-5反映: `==`はtimeoutではない）
   - 1k. capacity exhausted→CAPACITY_EXHAUSTED
   - 1l. Storage mapping: BUSY→WOULD_BLOCK, NO_SPACE→CAPACITY_EXHAUSTED, IO→STORAGE, CORRUPT→STORAGE_CORRUPT, COMMIT_UNKNOWN→STORAGE_COMMIT_UNKNOWN, UNSUPPORTED_SCHEMA→**STORAGE_CORRUPT**（r3 P1-5反映: docs/12:1542正本。UNSUPPORTEDではない）
   - 1m. commit OK→NINLIL_OK
2. Callback COMPLETE: result cache + token CONSUMED + slot release 1 FULL commit, commit前Receipt発行しない
3. Callback DEFER: 追加FULL writeなし, token値copy, payload pointer無効
4. Callback FATAL: RECOVERY_REQUIRED tombstone, positive Receipt 0, DEGRADED
5. Callback unknown action: CALLBACK_CONTRACT, recovery commit
6. on_reconcile REDELIVER: Nを増やさずINBOX戻し, 次のDELIVERY_STARTでN+1
7. on_reconcile KNOWN_RESULT: result commit
8. on_reconcile RETRY_LATER: descriptor fixed backoff, application指定delay無視
9. Completion timeout: EXPIRED tombstone, APPLICATION_COMPLETION_TIMEOUT, active slot解放
10. Restart: 旧process token→active復元しない, RECOVERY_REQUIREDへ収束
11. Health: callback contract fence→prio3, application failure→prio4, clear条件exact
12. Evidence allocation failure: evidence copy用のstorage allocation失敗→CAPACITY_EXHAUSTED, token不変（P1-5反映）
13. COMMIT_UNKNOWN後reopen: commit unknown→STORAGE_COMMIT_UNKNOWN返却後、same-runtimeでtokenがauthoritative ACTIVEなら残時間内再完了可能→NINLIL_OK。tokenが既にCONSUMED/EXPIREDならINVALID_STATE。authoritative stateはstorage readで確定（r2 P1-5反映: 曖昧化禁止、ACTIVE分岐追加）
14. Callback前後crash: DELIVERY_STARTED pre-commit後・callback dispatch前crash→restartでRECOVERY_REQUIRED。callback完了後・result commit前crash→restartでRECOVERY_REQUIRED（P1-5反映）
15. Reconcile claim crash: on_reconcile REDELIVER claim後・INBOX戻し前crash→restartでexact 1回INBOX戻しへ収束（P1-5反映）

**完了コマンド**: `ctest --test-dir build -R "delivery_complete|callback_lifecycle" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean

**依存**: B1-c完了（runtime_stepがcallbackをdispatch）。B1-b完了（service registration存在）

---

### B1-e: event_resume / event_discard management body（Risk 5）

**Normative根拠**:
- docs/12:1849-1968（EventFact park/resume/discard, management guard precedence, result field rules, request digest）
- docs/12:1805-1813（Targeted management linearization）
- docs/12:1929-1937（event_spool_revision, park cause, availability resume）
- docs/12:1950（unseen operation順序: ledger replay/conflict後、state/revision判定前にclock→catch-up）
- docs/04:239-240（EventFact NO_DEADLINE, retry cycle枯渇→PARKED_RETRY）
- 監査 §5: G3

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `src/model/scheduler_candidate.c/.h` | availability consume (work kind 2), manual resume |
| `src/model/resource_ledger.c/.h` | spool capacity release, management slot reserved→used |
| `src/model/domain_store_codec.c/.h`, `domain_store_body_codec.c/.h` | event record codec, management ledger record |
| `src/runtime/` 新規または既存 | event_resume body: guard precedence (ABI→role→lookup→ledger replay→**clock→catch-up**→state→revision→limit) → FULL commit |
| `src/runtime/` 新規または既存 | event_discard body: guard precedence (ABI→role→lookup→ledger replay→**clock→catch-up**→state→revision) → audit FULL commit → spool release |
| `tests/runtime/` | 負系/受入テスト新規 |

**rev2順序修正（P0-6反映）**: unseen operationの実装順はdocs/12:1950に従い、ledger replay/conflictの後、current state/revision判定前にclock→catch-upを実行する。rev1の「state/revision/limit後にclock/catch-up」は正本と逆であり修正する。Resume/discard双方に適用。

**禁止事項**:
- public ABI変更禁止
- management request digest (SHA-256) のexact byte layout (12:1970-1986) を推測で変更しない
- COUNTER_EXHAUSTED時のNOT_RESUMABLE absorbing stateを推測で緩和しない
- stub/TODO/compile-onlyの完成扱い禁止

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| G3 (management digest実装module) | **Solレビュー確定**: SHA-256 digest計算の実装場所（domain_store_body_codec内 or 新規）をB1-e計画レビューで確定。注: 実装設計事項でありpublic contract不足ではない（P2-2反映） | B1-eレビュー |
| P1-6 (event discard mismatch status) | **docs先行freeze**: expected_event_id/content_digest mismatchのexact API status/output/no-mutationをB1-e着手前にFableがcanonical doc (docs/12 or docs/13) の該当行を特定しdocs/workへfreeze。freezeなしでB1-e実装開始禁止（r3 P1-6反映） | B1-e着手前 / Fable |

**負系/受入試験（P1-6反映: API statusとresult kind分離）**:
1. Resume: wrong role→API status `NINLIL_E_UNSUPPORTED`, result kind設定なし（P1-6反映: API statusとresult kind分離）
2. Resume: NOT_FOUND→API status `NINLIL_E_NOT_FOUND`
3. Resume: wrong family→API status `NINLIL_OK`, result kind `NOT_EVENT_FACT`（P1-6反映）
4. Resume: PARKED + COUNTER_EXHAUSTED→API status `NINLIL_OK`, result kind `NOT_RESUMABLE`
5. Resume: 他のresumable cause→API status `NINLIL_OK`, result kind `RESUMED`
6. Resume: same operation/same digest replay→API status `NINLIL_OK`, result kind `ALREADY_RESUMED` (stored値exact)
7. Resume: same operation/different digest→API status `NINLIL_OK`, result kind `RESUME_CONFLICT`
8. Resume: stale spool revision→API status `NINLIL_OK`, result kind `STALE_SPOOL_REVISION`
9. Resume: 8 distinct operations後→API status `NINLIL_OK`, result kind `LIMIT_EXHAUSTED`
10. Discard: expected_event_id mismatch→**TBD**: exact API status/output/no-mutationはcanonical doc/vectorへfreeze後に確定（r2 P1-6反映: 推測断定禁止。確定手段: docs/12 or docs/13の該当行をcanonical freezeし、そのfile:lineを受入試験に引用する）
11. Discard: content_digest mismatch→**TBD**: 上記#10と同じ。canonical freeze後にexact status/output/no-mutationを確定（r2 P1-6反映）
12. Discard: acknowledge_required_receipt_absent!=1→API status `NINLIL_E_INVALID_ARGUMENT`
13. Discard: DISCARDED→API status `NINLIL_OK`, result kind `DISCARDED`, 1 FULL commit (audit+tombstone+payload erase), commit failure→spool解放せず
14. Discard: same operation replay→API status `NINLIL_OK`, result kind `ALREADY_DISCARDED` (stored値exact)
15. Linearization: clock取得→catch-up→management input順。same-time Receipt→cancel/discardより先
16. Availability resume: strictly larger epoch + resumable cause→READY, same/old epoch→no-op
17. event_spool_revision: admission=1, 各semantic FULL commitでchecked +1, terminal後はabsorbing
18. Call-trace受入: unseen operation時にledger replay→clock→catch-up→state判定の順でcall traceが記録されること（P0-6反映）

**完了コマンド**: `ctest --test-dir build -R "event_resume|event_discard" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean

**依存**: B1-c完了（runtime_stepがpark/availability consumeを駆動）。B1-b完了（EventFact admission存在）

---

### B1-f: cancel_request + transaction_query/list + capacity/metrics + offer_accept

**Normative根拠**:
- docs/12:1815-1847（DesiredState remote cancel, validation precedence, closed matrix）
- docs/12:1656-1803（Transaction/query/list, snapshot projection, list pagination）
- docs/12:2180-2257（Capacity accounting, 11 kind）
- docs/12:2258-2314（Metrics and health）
- docs/12:2436-2457（M1a unsupported behavior）
- docs/04:249-254（Cancel）, 04:279-282（query/list/capacity/metrics）
- 監査 §5: U4, C1, G2

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `src/model/deadline_projection.c/.h`, `desired_deadline_transition.c/.h` | cancel fence/remote cancel prepare |
| `src/model/desired_target_snapshot_internal.c/.h` | transaction snapshot projection |
| `src/model/domain_store_codec.c/.h` | transaction record decode for query/list |
| `src/runtime/domain_store_scanner.c/.h` | list pagination (prefix iteration, sequence ascending) |
| `src/model/resource_ledger.c/.h` | capacity snapshot read (11 kind) |
| `src/runtime/` 新規または既存 | cancel_request body: role/family/lookup → clock/catch-up → fence/remote prepare → closed matrix result |
| `src/runtime/` 新規または既存 | transaction_query/list body: read-only projection |
| `src/runtime/` 新規または既存 | capacity_snapshot body: 11 kind exact order |
| `src/runtime/` 新規または既存 | metrics_snapshot body: logical snapshot, counter不増 |
| `src/runtime/` 新規または既存 | offer_accept body: full validation precedence (P1-2反映) |
| `tests/runtime/` | 負系/受入テスト新規 |

**禁止事項**:
- public ABI変更禁止
- cancelのremote send gate 3-state (NEVER_INVOKED/INVOKED_CLOSED/WOULD_BLOCK_RETRYABLE) を推測で緩和しない
- transaction_query/listのdomainをreceiver-side inboundへ拡張しない
- stub/TODO/compile-onlyの完成扱い禁止

**未確定事項の解消割当**:
| 監査ID | 解消方法 | 割当 |
|--------|----------|------|
| U4 (query/list domain store read path) | **Solレビュー確定**: query/list readの実装seam（domain_store_scannerとのexact対応）をB1-f計画レビューで確定。d3s phaseとは無関係（r2 P0-3反映）。注: 実装設計事項でありpublic contract不足ではない（P2-2反映） | B1-fレビュー |
| C1 (query/list/capacity buffer規則) | **rev2修正（P2-1反映）**: C1は「矛盾・緊張関係」ではなくscanner適合確認事項。12:2406/12:1781-1785/12:2256-2257の規則に矛盾はない。B1-f着手前にFableがscanner適合確認をdocs/workへ記録 | B1-f着手前 |
| G2 (offer_accept validation precedence) | 実装で解消: full validation precedence (P1-2反映) | B1-f実装内 |

**負系/受入試験**:
1. cancel: wrong role→UNSUPPORTED, EventFact→UNSUPPORTED, NOT_FOUND, ALREADY_TERMINAL
2. cancel: FENCED_BEFORE_DISPATCH (local no-delivery fence 1 FULL commit)
3. cancel: PENDING_REMOTE_FENCE (cancel attempt/record FULL commit)
4. cancel: persist済みcancel kind repeat→same kind返却, current_outcomeだけ更新
5. cancel: closed matrix全6行 (12:1838-1846) exact match
6. query: active/retained→OK, unknown/receiver-side/cleaned→NOT_FOUND
7. query: BUFFER_TOO_SMALL→target_countだけrequired値, target array未変更
8. query: family-specific all-field rule (12:1763-1774) exact match
9. query: bad element header時→配列不変、ABI_MISMATCH（P1-7反映）
10. query: 同一read snapshot: query中にstate変化しても返却snapshotはcall時点（P1-7反映）
11. list: sequence ascending, after exclusive, partial page OK, has_more exact
12. list: item_capacity 0→items NULL, count 0, has_more判定
13. list: family/time/terminal filter全組合せ (`ninlil_query_t`のfamily_mask全bit, time range, terminal filter)（r2 P1-7反映: filterはlistの`ninlil_query_t`が使用。queryではない）
14. list: 余剰要素不変: item_capacity > actual時、余剰要素はcaller値のまま不変（P1-7反映）
15. list: bad element header→配列不変（P1-7反映）
16. capacity: 11 kind exact order, BUFFER_TOO_SMALL→entry_count=11
17. capacity: bad element header時→全配列不変、ABI_MISMATCH（r2 P1-7反映）
18. capacity: blocked flag/epoch/high-waterのrestart後persist検証（P1-7反映）
19. metrics: 全counter exact increment rule (12:2262-2276), 自身callでcounter不増
20. metrics: saturation: counter最大値到達後のoverflow挙動（P1-7反映）
21. metrics: 全counter境界値 (0, 1, max-1, max)（P1-7反映）
22. offer_accept（r5 P1-1反映: precedence順序修正。docs/12:2394正本: outer validation→context-zero→wrong-thread→re-entry）:
    - 22a. runtime NULL→INVALID_ARGUMENT
    - 22b. offer_id NULL→INVALID_ARGUMENT
    - 22c. out_result NULL→INVALID_ARGUMENT
    - 22d. out_result bad ABI header→ABI_MISMATCH（注: runtimeはopaque handle、offer_idはheaderless `ninlil_id128_t`のためheader検査対象外）
    - 22e. execution context zero→DEGRADED（docs/12:2394。wrong-thread/re-entryより先）
    - 22f. wrong thread→WRONG_THREAD
    - 22g. callback re-entry→REENTRANT
    - 22h. well-formed→UNSUPPORTED, out_result zeroing (INVALID/zero)

**完了コマンド**: `ctest --test-dir build -R "cancel_request|transaction_query|transaction_list|capacity_snapshot|metrics_snapshot|offer_accept" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean

**依存**: B1-c完了（runtime_stepがcancel send/reduceを駆動）。B1-b完了（transaction存在）

---

### B1-g: cross-API crash/restart E2E integration gate（P0-7反映: 新規追加）

**Normative根拠**:
- docs/12:1160-1207（Stage 1-9, recovery）
- docs/12:2164（crash recovery determinism）
- docs/04:351-394（Atomic boundary, crash recovery）
- master plan §0（durable path crash/restart収束）

**目的**: 各段階の局所テストでは証明できないcross-API durable pathを検証する。register→submit→step→ingress→callback/deferred complete→queryのfull lifecycleを、crash/recreate/service reattach後に同じID・reservation・Outcomeへ収束させる。

**編集範囲**:
| ファイル | 変更 |
|----------|------|
| `tests/integration/` 新規 | cross-API E2E fault injection test suite |

**禁止事項**:
- public ABI変更禁止
- 新規src実装禁止（B1-a〜B1-fの既存実装のみ使用）
- stub/TODO/compile-onlyの完成扱い禁止

**Fault matrix（r2 P0-7反映: 全主要FULL commitの前後 + COMMIT_UNKNOWN網羅）**:

| # | Crash point | 期待収束 |
|---|-------------|----------|
| 1 | service_register FULL commit前 | restart→service未登録（ID未公開）、再registerで正常 |
| 2 | service_register FULL commit後 | restart→service登録済み、reattachでcallback復元 |
| 3 | service_register COMMIT_UNKNOWN | restart→0回または1回registrationへ収束 |
| 4 | submit admission FULL commit前 | restart→transaction未生成（ID未公開）、再submitで正常 |
| 5 | submit admission FULL commit後 | restart→transaction active、same ID/reservation/outbox復元 |
| 6 | submit COMMIT_UNKNOWN | restart→0回または1回admissionへ収束 |
| 7 | runtime_step micro-op FULL commit前 | restart→micro-op未実行、recovery workで再実行 |
| 8 | runtime_step micro-op FULL commit後 | restart→micro-op完了済み、次micro-opへ進行 |
| 9 | runtime_step COMMIT_UNKNOWN | restart→cursor推測せずrecovery scanで収束 |
| 10 | callback DELIVERY_STARTED pre-commit後、dispatch前 | restart→RECOVERY_REQUIRED tombstone |
| 11 | callback DELIVERY_STARTED COMMIT_UNKNOWN | restart→authoritative truth判定: committedならRECOVERY_REQUIRED tombstoneへ収束（docs/12:1477）; 未committedならcallback未実行のまま再dispatch可能（docs/13:1373） |
| 12 | callback完了後、result commit前 | restart→RECOVERY_REQUIRED tombstone |
| 13 | callback result COMMIT_UNKNOWN | restart→authoritative truth判定: committedならtoken CONSUMED + result cache有効; 未committedならcallback再実行せずRECOVERY_REQUIREDへ収束（docs/12:1477, docs/13:1373） |
| 14 | reconcile result COMMIT_UNKNOWN | restart→authoritative truth判定: committedならaction完了済み（REDELIVER/KNOWN_RESULT/RETRY_LATER persist）; 未committedならRECOVERY_REQUIREDへ収束（docs/13:1373） |
| 15 | delivery_complete FULL commit前 | restart→token active復元しない、RECOVERY_REQUIRED |
| 16 | delivery_complete FULL commit後 | restart→token consumed、result cache有効 |
| 17 | delivery_complete COMMIT_UNKNOWN | restart→0回または1回completionへ収束 |
| 18 | event_resume FULL commit前 | restart→event PARKEDのまま（resume未公開） |
| 19 | event_resume FULL commit後 | restart→event RESUMED、spool revision increment済み |
| 20 | event_resume COMMIT_UNKNOWN | restart→0回または1回resumeへ収束 |
| 21 | event_discard FULL commit前 | restart→event active、spool解放せず（discard未公開） |
| 22 | event_discard FULL commit後 | restart→event DISCARDED、spool解放済み |
| 23 | event_discard COMMIT_UNKNOWN | restart→0回または1回discardへ収束 |
| 24 | cancel FULL commit前 | restart→cancel未記録（cancel kind未公開） |
| 25 | cancel FULL commit後 | restart→cancel kind persist済み、same kind返却 |
| 26 | cancel COMMIT_UNKNOWN | restart→0回または1回cancel記録へ収束 |
| 27 | destroy active token recovery commit前 | restart→token active、次create recoveryで収束 |
| 28 | destroy active token recovery commit後 | restart→token EXPIRED/RECOVERY_REQUIRED |
| 29 | destroy COMMIT_UNKNOWN | restart→0回または1回token invalidationへ収束 |

**受入条件（r3 P0-7反映: commit前/後/UNKNOWNで条件分離、callback lifecycle COMMIT_UNKNOWN追加）**:
- 「commit前」crash: 当該mutationは未公開。restart後に当該操作のeffectが見えないこと（ID/reservation/Outcomeの公開なし）。再操作で正常に完了できること
- 「commit後」crash: 当該mutationは公開済み。restart後にsame ID/reservation/Outcomeが復元されること
- 「COMMIT_UNKNOWN」crash: restart後に0回または1回のmutationへ収束すること（2回適用されない）
- service reattach後にcallback dispatchが正常動作
- どのcrash pointでもdata loss/corruption/duplicationがない
- full ctest (`--no-tests=error`) pass

**完了コマンド**: `ctest --test-dir build -R "b1_integration_e2e" --output-on-failure --no-tests=error` (ASan+UBSan build)

**期待出力**: 全テストgreen, strict warnings 0, ASan/UBSan clean

**依存**: B1-a〜B1-f全完了。A4完了

---

## 3. 段階依存グラフ

```
B1-a (create/destroy + library実体化)
  ├── B1-b (register/submit)
  │     ├── B1-c (runtime_step)
  │     │     ├── B1-d (delivery/callback)
  │     │     ├── B1-e (event mgmt)
  │     │     └── B1-f (cancel/query/list/cap/metrics/offer)
  │     └── (B1-d/e/fもB1-bのtransaction/serviceに依存)
  ├── (全段階がB1-aのRuntime handleに依存)
  └── B1-g (cross-API E2E) ← B1-a〜B1-f全完了

外部依存:
  A4 ──→ B1-a (Stage 5 domain recovery, 受入gate)
  A1 ──→ B1-c (d3s3 cross-row)
  A2 ──→ B1-c (witness chain)
  A3 ──→ B1-c (D3 validation, P0-3反映)
  A4 ──→ B1-c (D4 convergence, P0-3反映)
```

## 4. 未確定/不足の解消割当まとめ（rev2修正）

| 監査ID | 種別（rev2） | 解消方法 | 割当段階 | タイミング |
|--------|------|----------|----------|------------|
| U1 | 未確定 | docs先行freeze | B1-a | 着手前 |
| U2 | 未確定 | docs先行freeze | B1-a | 着手前 |
| U3 | ~~未確定~~ → 解消済み（P0-5反映） | B1-aスコープ内で実装 | B1-a | 実装内 |
| U4 | ~~未確定~~ → 実装設計（P2-2反映, r2 P0-3反映: d3s無関係） | Solレビュー確定 | B1-f | レビュー時 |
| U5 | ~~未確定~~ → 解消済み（P0-4反映: B1スコープ外） | NCL1はB1除外、後続トランチへ | - | 解消済み |
| U6 | ~~未確定~~ → 実装設計（P2-2反映） | Solレビュー確定 | B1-d | レビュー時 |
| C1 | ~~矛盾~~ → scanner適合確認（P2-1反映） | docs先行freeze (適合確認) | B1-f | 着手前 |
| C2 | ~~矛盾~~ → 解消済み（r2 P0-3反映: D3-Sはrecovery scanner、B1-c編集資産から完全除外） | 設計修正で解消 | B1-c | 解消済み |
| G1 | 不足（実装設計, P2-2反映） | Solレビュー確定 | B1-a | レビュー時 |
| G2 | 不足 | 実装で解消 (full validation precedence, P1-2反映) | B1-f | 実装内 |
| G3 | 不足（実装設計, P2-2反映） | Solレビュー確定 | B1-e | レビュー時 |
| G4 | 不足 → 解消済み（P0-9反映: docs/14:1970にlayout存在） | 実装module配置のみdocs/workで決定 | B1-b | レビュー時 |
| G5 | 不足（実装設計, P2-2反映） | Solレビュー確定 | B1-d | レビュー時 |
| G6 | ~~不足~~ → 解消済み（P0-4反映: B1スコープ外） | 後続トランチへ | - | 解消済み |

## 5. 全段階共通の禁止事項

1. `include/ninlil/*.h` のpublic ABI変更禁止（field順/型/定数値/signature不変）
2. docs/17 (foundation-domain-store) 変更禁止
3. git操作禁止（本計画は素案。commit/PRはorchestrator指示待ち）
4. stub / TODO / compile-only / 未接続candidateの完成扱い禁止
5. KGuard固有語彙のportable Core流入禁止
6. 推測でsemanticを補完しない。不明箇所はdocs先行freezeまたはSolレビュー確定を待つ
7. CI赤（Linux/macOS + ASan/UBSan + ESP-IDF build + consumer link）でのmerge禁止（P1-8反映）
8. 各段階のNormative根拠に列挙したfile:line以外のdocsを変更しない
9. NCL1 codec / control_session / logical_sessionをB1内で接続しない（P0-4反映）
10. normative semanticの追加・変更はcanonical doc/vectorへfreezeし、レビュー判断だけで確定しない（P0-9反映）

## 6. 役割（master plan §3再掲）

- **Fable**: 本素案の改訂、docs先行freeze文書作成、統合QA、進捗台帳
- **Codex GPT-5.6 Sol high**: 各段階計画レビュー（P0/P1解消まで実装開始禁止）
- **OpenCode Qwen**: 主実装（限定編集範囲）
- **Grok grok-4.5**: 全diffコードレビュー
- **Codex GPT-5.6 Sol xhigh**: 重大境界レビュー（oracle/production, ABI/storage format）

## 7. リスク（本計画固有）

| # | リスク | 影響 | 緩和 |
|---|--------|------|------|
| 1 | A4完了が遅延するとB1-a受入がblock | B1-a以降全段階 | B1-aのコード準備（Stage 1-9 body記述）はA4前に可能。受入テストはA4完了後に実行。B1-gはA4完了が絶対前提 |
| 2 | ~~d3s1/d3s2/d3s3とring laneの対応が複雑~~ → 解消（P0-3反映: D3-Sはrecovery scannerでありring laneと無関係） | - | - |
| 3 | 22 work kindのtie-breakとcrash recoveryの組合せ爆発 | B1-c | per-kind closed coverage表（§B1-c 22 work kind表）で全22 kind×6軸の実体接続を要求。class別に段階検証 |
| 4 | delivery_completeの13段階ordered tableとcallback lifecycleのstate machineが複雑 | B1-d | 各段階を独立テストで検証。ordered tableの各行を個別test case化（P1-5反映） |
| 5 | EventFact managementのledger replay/conflictとavailability epochの相互作用 | B1-e | operation ID/digest/revisionの3軸を独立にテスト。availability resumeは別test suite |
| 6 | cross-API crash/restart E2Eのfault matrix規模 | B1-g | 29 crash point（全主要FULL commit前後+COMMIT_UNKNOWN、callback lifecycle含む）を段階的に追加。commit前/後/UNKNOWNで受入条件分離 |

## 8. Semantic freeze authority（P0-9反映: 新規追加）

- docs/12 (Foundation M1a C ABI) が正本。docs/12が委譲するdocs/13 (work kind semantic), docs/14 (ports and simulator, canonical submission layout), docs/17 (foundation domain store) もnormative authorityを持つ
- canonical submission digestのexact byte layoutはdocs/14:1970に存在する（P0-9反映）
- 実装配置（module選択）はdocs/workで決定可
- normative semanticの追加・変更はcanonical doc/vectorへfreezeし、レビュー判断だけで確定しない
- 監査対象はdocs/12 + docs/12が委譲するdocs/13/14/17を含む

## 9. レビュー履歴

| 日時 | レビュア | 結果 |
|------|----------|------|
| 2026-07-21 | Fable起草（本書） | draft rev1。Sol highレビュー待ち |
| 2026-07-21 | Sol high | r1レビュー: NO-GO P0=9 P1=8 P2=4 |
| 2026-07-21 | Fable改訂 | draft rev2。r1全所見反映 |
| 2026-07-22 | Sol high | r2レビュー: NO-GO P0=3 P1=5 P2=3（r1から改善） |
| 2026-07-22 | Fable改訂 | draft rev3。r2全所見反映 |
| 2026-07-22 | Sol high | r3レビュー: NO-GO P0=3 P1=4 P2=1（P1-7/P2-1/P2-3解消確認） |
| 2026-07-22 | Fable改訂 | draft rev4。r3全所見反映。解消証明表下記 |
| 2026-07-22 | Sol high | r4レビュー: NO-GO P0=2 P1=1 P2=1（P0-3/P1-4/P1-5/P1-6解消確認） |
| 2026-07-22 | Fable改訂 | draft rev5。r4全所見反映。解消証明表下記 |
| 2026-07-22 | Sol high | r5レビュー: NO-GO P0=1 P1=1 P2=1（P0-7解消確認） |
| 2026-07-22 | Fable改訂 | draft rev6。r5全所見反映。解消証明表下記 |

### r5所見 解消証明表

| 所見ID | (a) 要求要旨 | (b) 改訂箇所と要旨 | (c) 解消根拠 |
|--------|-------------|-------------------|-------------|
| P0-8 | RECONCILE_CALLBACK cursorがclaim commitになっているが正本はresult commit。表内にTBDが残りclosed specでない | §B1-c 22-kind表 kind#10: cursor列を「reconcile **result commit**内に配置（docs/12:2159）」へ修正。FULL commit列も「claim commit + action commit (cursor含む)」へ修正。表注からTBDを削除し「closed specification」を宣言。multi-commit cursor配置をDELIVERY_CALLBACK=DELIVERY_STARTED commit内、RECONCILE_CALLBACK=result commit内と個別固定 | docs/12:2159の正本と一致。表内にTBD/未確定語がゼロ。全22行×6軸がfile:line付きで固定 |
| P1-1 | offer_accept precedenceがwrong-thread/re-entryの後。正本はcontext-zero→wrong-thread→re-entry | §B1-f試験#22の順序を22e(DEGRADED)→22f(WRONG_THREAD)→22g(REENTRANT)へ修正。監査§2.5のprecedence記述も同一順序へ修正 | docs/12:2394の正本順序（outer validation→context-zero→wrong-thread→re-entry）と一致 |
| P2-4 | master plan版不整合（編集対象外） | §10「本レビューサイクルでは解消不可」を維持。解消条件+B1-a着手gate独立性を記述済み | 編集対象外のため直接解消不可。本計画の進行をblockしないことを明示済み |

### r4所見 解消証明表

| 所見ID | (a) 要求要旨 | (b) 改訂箇所と要旨 | (c) 解消根拠 |
|--------|-------------|-------------------|-------------|
| P0-7 | callback lifecycle COMMIT_UNKNOWNの期待値が「0回または1回」のまま。authoritative truth別の最終状態を固定せよ | §B1-g fault matrix #11/#13/#14をauthoritative truth判定へ書き換え: #11 DELIVERY_STARTED committed→RECOVERY_REQUIRED / 未committed→再dispatch可（docs/12:1477, docs/13:1373）。#13 callback result committed→CONSUMED+result cache / 未committed→callback再実行せずRECOVERY_REQUIRED。#14 reconcile result committed→action完了 / 未committed→RECOVERY_REQUIRED | 各行がcommitted/未committedの両truthに対してexact最終状態を固定。「0回または1回」の曖昧表現を削除。docs/12:1477, docs/13:1373を典拠として明記 |
| P0-8 | 22-kind表がclosedでない: DEFER cursor誤り、ATTEMPT_PREPAREのEntropy Port欠落、sendのClock/TxGate欠落、multi-commit cursor配置未固定 | §B1-c 22-kind表修正: kind#9 DELIVERY_CALLBACK cursor→「DELIVERY_STARTED success commit内に配置（callback前）。DEFERは追加write 0だがcursorはDELIVERY_STARTEDに含まれ済み」（docs/12:2152）。kind#11/#13 ATTEMPT_PREPARE Port列→「Entropy Port」（docs/12:520）。kind#12/#14 send Port列→「fresh Clock sample + TxGate transition + Bearer send Port」（docs/12:520, 2164）。kind#10 RECONCILE_CALLBACK cursor→「claim commit内に配置」。表注を修正: 正本file:line未明示の列値はB1-c着手前にFableが追記（TBD+確定手段明記） | DEFER cursorが正本（DELIVERY_STARTEDに含まれる）と一致。Entropy/Clock/TxGate Portが明示。multi-commit kindのcursor配置が最初のcommitへ固定。後決め余地をTBD+確定手段で閉じた |
| P1-1 | destroy/offer_accept/query/list/capacity/metricsにDEGRADED欠落。offer_accept試験がopaque runtime/headerless id128にbad ABI headerを要求 | 監査§2.2 destroy、§2.5 offer_accept、§2.9 query、§2.10 list、§2.13 capacity、§2.14 metricsのerror分類にDEGRADED (execution context zero, docs/12:2394)追加。offer_accept分類でABI_MISMATCH対象をout_result headerのみに修正（runtime opaque、offer_id headerless）。計画§B1-f試験#22dをout_result headerのみへ修正、#22gにcontext-zero DEGRADED追加 | create以外全14 APIのerror分類にDEGRADEDが含まれた。offer_acceptのABI header検査対象が実在するout_result headerに限定された |
| P2-4 | master plan版不整合。将来修正割当は解消証明にならない | §10を「本レビューサイクルでは解消不可」へ修正。解消条件（orchestrator修正）とB1-a着手gate独立性を明記 | 編集対象外のため直接解消不可を正直に明記。将来割当ではなく解消条件として記述。本計画の進行をblockしないことを明示 |

### r3所見 解消証明表

| 所見ID | (a) 要求要旨 | (b) 改訂箇所と要旨 | (c) 解消根拠 |
|--------|-------------|-------------------|-------------|
| P0-3 | 監査§2.12 runtime_step資産一覧とU4にd3s接続が残り「live seam無関係」と矛盾 | 監査§2.12「利用すべきsrc資産」からd3s1/d3s2/d3s3を削除し「A1-A4 recovery scan専用」注記追加。U4の「d3s1/d3s2/d3s3のどのphase」記述を削除し「domain_store_scannerとのseam」へ修正 | 監査内でd3sがruntime_step資産として参照される箇所がゼロになった。U4もd3sを参照しない。計画§B1-cの「編集資産に含めない」と整合 |
| P0-7 | crash matrixにDELIVERY_STARTED/callback result/reconcile resultのCOMMIT_UNKNOWNがない | §B1-g fault matrixに#11(DELIVERY_STARTED COMMIT_UNKNOWN)、#13(callback result COMMIT_UNKNOWN)、#14(reconcile result COMMIT_UNKNOWN)の3行追加。計29 crash point | docs/14:934のDELIVERY_STARTED durable記録、callback result commit、reconcile action commitの各FULL commitにCOMMIT_UNKNOWN分岐が設けられた。前後crashだけでなくunknown両truthの収束を検証可能 |
| P0-8 | 22-kind表がclosed coverageでない: RECONCILE_CALLBACK transitions誤り、DELIVERY_CALLBACK DEFER誤読、cursor後決め | §B1-c 22-kind表修正: kind#10 RECONCILE_CALLBACKを「transitions 1」へ（docs/12:2242正本）。kind#9 DELIVERY_CALLBACKのFULL commit列を「COMPLETE→result commit; DEFER→追加write 0」へ明示。cursor列を全行「micro-opのFULL commit内（docs/12:2150-2162）」へ固定（DEFER時はcursor updateなし）。表注を「closed specification、後決めではない」へ修正 | 各列値がdocs/12のfile:lineから直接導出され、実装受入時の後決め余地がない。RECONCILE_CALLBACKのtransition数、DELIVERY_CALLBACKのDEFER時write、cursorのexact commit placementが正本と一致 |
| P1-1 | cancel_requestだけ「Storage系」のまま | 監査§2.6 cancel_request error分類を「WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN」へexplicit展開 | 監査全14 APIのerror分類に「Storage系」表記がゼロになった |
| P1-4 | entropy exhaustion時の予約逆順releaseが受入条件にない（正本順序: reservation→ID draw） | §B1-b試験#16を「entropy 4-draw exhaustion→ENTROPY + reserve済みkindを逆順release + commit抑止」へ修正。docs/12:1032の順序（reservation→transaction ID draw）を明記 | 正本順序でreservation後にentropy drawするため、entropy failure時にreservation解放が必要。受入条件に逆順releaseが明記された |
| P1-5 | delivery UNSUPPORTED_SCHEMA→UNSUPPORTEDは誤り。正本docs/12:1542はSTORAGE_CORRUPT | §B1-d試験1lのUNSUPPORTED_SCHEMA mappingを「STORAGE_CORRUPT」へ修正 | docs/12:1542の正本と一致 |
| P1-6 | event mismatch TBDに着手前gate・担当が未割当 | §B1-e「未確定事項の解消割当」表にP1-6行追加: 「B1-e着手前 / Fable」がcanonical docの該当行を特定しdocs/workへfreeze。freezeなしでB1-e実装開始禁止 | 担当(Fable)、gate(B1-e着手前)、確定手段(canonical doc該当行のdocs/work freeze)が明記された |
| P2-4 | master plan版表示不整合（編集対象外） | §10「既知の外部不整合」に確定手段追加: orchestrator(Fable)がB1-a着手前までにmaster plan冒頭をrev3へ修正 | 編集対象外のため直接修正不可だが、担当・期限・確定手段が明記された |

## 10. 既知の外部不整合（編集対象外・本レビューサイクルでは解消不可）

- **master plan版表示不整合（r2 P2-4, r3/r4継続）**: `docs/work/2026-07-21-master-plan.md` の冒頭は`rev2`、履歴上の最新版は`rev3`で不整合（master-plan:3, master-plan:71）。本ファイルの編集対象外（変更禁止範囲）のため、本レビューサイクルでは解消不可。**解消条件**: orchestrator (Fable) がmaster planの冒頭版表示を`rev3`へ修正した時点で解消。本計画のB1-a着手gateとは独立（master plan修正を待たずB1-a着手可）。
