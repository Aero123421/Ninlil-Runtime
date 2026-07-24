# B1事前監査: public Runtime body実装トランチ 契約抽出

状態: Read-only audit / B1実装準備 / **rev6**（Sol high r5レビュー反映）
対象: `include/ninlil/runtime.h` 宣言のpublic Runtime API全14関数
正本: docs/12 (Foundation M1a C ABI) > docs/04 (Runtime API and Storage) > docs/02 (Application Contracts)
委譲正本（P0-9反映）: docs/12が委譲するdocs/13 (work kind semantic), docs/14 (ports and simulator, canonical submission layout), docs/17 (foundation domain store) もnormative authorityを持つ。監査対象に含む。

## 0. 監査範囲と制約

- 本ファイルは新規1ファイル出力のみ。コード変更・docs/17等変更・git操作なし。
- 推測でsemanticを補完しない。不明は不明と記載。
- 典拠は `file:line` 形式で付与。
- normative semanticの追加・変更はcanonical doc/vectorへfreezeし、レビュー判断だけで確定しない（P0-9反映）。

## 1. 14 API関数 一覧

| # | Function | Header宣言 | docs/12 §12 signature | docs/04 family |
|---|----------|-----------|----------------------|----------------|
| 1 | `ninlil_runtime_create` | runtime.h:133-136 | 12:2319-2322 | 04:275 |
| 2 | `ninlil_runtime_destroy` | runtime.h:138 | 12:2324 | 04:275 |
| 3 | `ninlil_service_register` | runtime.h:140-144 | 12:2326-2330 | 04:276 |
| 4 | `ninlil_submit` | runtime.h:146-149 | 12:2332-2335 | 04:277 |
| 5 | `ninlil_offer_accept` | runtime.h:151-154 | 12:2337-2340 | 04:285 |
| 6 | `ninlil_cancel_request` | runtime.h:156-159 | 12:2342-2345 | 04:277 |
| 7 | `ninlil_event_resume` | runtime.h:161-165 | 12:2347-2351 | 04:278 |
| 8 | `ninlil_event_discard` | runtime.h:167-171 | 12:2353-2357 | 04:278 |
| 9 | `ninlil_transaction_query` | runtime.h:173-176 | 12:2359-2362 | 04:279 |
| 10 | `ninlil_transaction_list` | runtime.h:178-181 | 12:2364-2367 | 04:279 |
| 11 | `ninlil_delivery_complete` | runtime.h:183-186 | 12:2369-2372 | 04:280 |
| 12 | `ninlil_runtime_step` | runtime.h:188-191 | 12:2374-2377 | 04:281 |
| 13 | `ninlil_capacity_snapshot` | runtime.h:193-195 | 12:2379-2381 | 04:282 |
| 14 | `ninlil_metrics_snapshot` | runtime.h:197-199 | 12:2383-2385 | 04:282 |

## 2. API別 契約表

### 2.1 ninlil_runtime_create

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `const ninlil_runtime_config_t *config`, `const ninlil_platform_ops_t *platform`, `ninlil_runtime_t **out_runtime` | runtime.h:133-136 |
| 戻り値 | `ninlil_status_t` | runtime.h:133 |
| struct_size規約 | config/platformは`NINLIL_STRUCT_HEADER`必須。`abi_version == NINLIL_ABI_VERSION`、`struct_size >= M1a required末尾field` | 12:204-209 |
| nullability | config, platform, out_runtimeすべてnon-NULL required。NULLは`NINLIL_E_INVALID_ARGUMENT` | 12:2425 |
| 受理条件 | Stage 1-9 exact order。role=CONTROLLER/ENDPOINT、environment=TESTのみ。platform 8 sub-vtable全required | 12:1156-1174 |
| 状態遷移 | 成功時`*out_runtime` non-NULL publish。失敗時常にNULL | 12:1162, 2398 |
| durable義務 | Stage 5でprofile binding/counter/capacity 17 recordsを1 FULL commit。Stage 7でCLOCK_BASELINE比較・FULL更新 | 12:1268, 1172 |
| error分類 | ABI_MISMATCH / INVALID_ARGUMENT / UNSUPPORTED / CONFLICT (identity rotation regressive epoch) / WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN / CLOCK_UNCERTAIN / DEGRADED / ENTROPY | 12:1178-1207（r2 P1-1反映: WRONG_THREAD/REENTRANT削除。createはruntime生成前callのためthread ownership/re-entry対象外） |
| restart后可視性 | Stage 5 recovery scan/fence完了後にだけBearer open。既存namespaceはprofile exact match必須 | 12:1170-1171, 1209-1231 |
| docs/02接続 | Runtime = 有限資源を所有し要求を実行・追跡するNinlil instance | 02:35 |
| 利用すべきsrc資産 | `src/model/runtime_store_bootstrap.c/.h` (L2a bootstrap codec), `src/model/runtime_store_codec.c/.h` (envelope/CRC), `src/runtime/runtime_store_stage5_seam.c/.h` (Stage 5 seam), `src/runtime/stage5_empty_metadata.c/.h`, `src/model/runtime_lifecycle_model.c/.h` |  |

### 2.2 ninlil_runtime_destroy

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime` | runtime.h:138 |
| 戻り値 | `ninlil_status_t` | runtime.h:138 |
| struct_size規約 | N/A (opaque handle) | 12:448-449 |
| nullability | runtime non-NULL required | 12:2415 |
| 受理条件 | owner thread、callback外。Validation成功後DESTROYING fence不可逆 | 12:2415-2416 |
| 状態遷移 | DESTROYING後handle consume。active token group recovery-fence → bearer.close → storage.close → deallocate | 12:2416-2419 |
| durable義務 | Active tokenあれば1 FULL commitでEXPIRED/RECOVERY_REQUIRED/OUTCOME_UNKNOWNへ。operation kind 19 | 12:2417 |
| error分類 | INVALID_ARGUMENT / WRONG_THREAD / REENTRANT / DEGRADED (execution context zero) / WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN | 12:2415-2419, 12:2394（r4 P1-1反映: DEGRADED追加） |
| restart后可視性 | destroy failureでもjournal/DELIVERY_STARTEDを削除せず。次create recoveryで収束 | 12:2421 |
| docs/02接続 | Runtime lifecycle終了。non-terminal transactionはstorageに残し次createでrecovery | 02:35 |
| 利用すべきsrc資産 | `src/model/runtime_lifecycle_model.c/.h`, `src/runtime/runtime_store_orchestrator.c/.h` |  |

### 2.3 ninlil_service_register

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_service_descriptor_t *descriptor`, `const ninlil_service_callbacks_t *callbacks`, `ninlil_service_t **out_service` | runtime.h:140-144 |
| 戻り値 | `ninlil_status_t` | runtime.h:140 |
| struct_size規約 | descriptor/callbacksはSTRUCT_HEADER必須 | 12:1285-1318, 1451-1456 |
| nullability | runtime, descriptor, callbacks, out_serviceすべてnon-NULL。callbacks内function pointerはrole×familyでNULL可 | 12:2425, 1463 |
| 受理条件 | M1a family=EVENT_FACT/DESIRED_STATEのみ。role×family×direction×authority×apply closed matrix。descriptor validation多数 | 12:1321-1390 |
| 状態遷移 | 初回: FULL commit → handle publish。Exact再登録: same handle/no write。Conflict: `NINLIL_E_CONFLICT` | 12:1380-1387 |
| durable義務 | 初回unique registrationはSERVICE slotと同じFULL transactionへpersist | 12:1382 |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / UNSUPPORTED / CONFLICT / DEGRADED (context-zero) / WOULD_BLOCK (Storage BUSY) / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN | 12:1330-1387（r2 P1-1反映: DEGRADED/WOULD_BLOCK追加） |
| restart后可視性 | Stage 5でpersist済みservice registry load。attachment 0件。再attachまでcallback/send 0 | 12:1385 |
| docs/02接続 | ServiceDescriptor = application serviceが登録する静的通信契約。Command/Event familyのdirection/authority/apply contractを固定 | 02:173-198 |
| 利用すべきsrc資産 | `src/model/submission_admission.c/.h` (descriptor validation logic), `src/contract/abi_contract.c/.h` |  |

### 2.4 ninlil_submit

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_service_t *service`, `const ninlil_submission_t *submission`, `ninlil_submission_result_t *out_result` | runtime.h:146-149 |
| 戻り値 | `ninlil_status_t` (API invocation error)。Semantic rejectionは`NINLIL_OK + REJECTED` | runtime.h:146, 12:198 |
| struct_size規約 | submission/resultはSTRUCT_HEADER必須 | 12:1563-1612 |
| nullability | service, submission, out_resultすべてnon-NULL。targets: count==0→NULL, count>0→non-NULL | 12:1617, 2425 |
| 受理条件 | Sender handleのみ。Receiver handleは`REJECTED / UNSUPPORTED_DIRECTION`。M1a target exactly 1。idempotency 1-64 bytes。family固有deadline/evidence規則 | 12:1388, 1617-1638 |
| 状態遷移 | ADMITTED_READY: transaction ID生成、FULL admission commit。ALREADY_ADMITTED: 既存返却。REJECTED/IDEMPOTENCY_CONFLICT: caller ownership | 12:1639-1654 |
| durable義務 | Admission commit前に全byteをRuntime所有storageへcopy/commit。transaction+target+descriptor ref+reservation+idempotency+outboxを1 FULL transaction | 04:292-293, 04:351-360 |
| error分類 | API: INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN / ENTROPY / DEGRADED / CLOCK_UNCERTAIN / CAPACITY_EXHAUSTED / WOULD_BLOCK。Semantic: REJECTED + reason多数 | 12:1639-1654（P1-1反映: Storage/Port status追加） |
| restart后可視性 | FULL admission commit OK後だけ所有権成立。commit unknownは`NINLIL_E_STORAGE_COMMIT_UNKNOWN` | 12:1634 |
| docs/02接続 | Submission = admission前にcallerが提出する要求。ApplicationData = admission後にRuntimeが所有。DesiredStateCommand/EventFactのfamily規則 | 02:37-38, 02:47-83, 02:200-219 |
| 利用すべきsrc資産 | `src/model/submission_preflight.c/.h` (syntax/schema/content validation), `src/model/submission_admission.c/.h` (admission control/idempotency/quota), `src/model/scheduler_candidate.c/.h` (scheduler owner creation), `src/model/resource_ledger.c/.h` + `resource_ledger_batch.c/.h` (capacity reservation) |  |

### 2.5 ninlil_offer_accept

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_id128_t *offer_id`, `ninlil_submission_result_t *out_result` | runtime.h:151-154 |
| 戻り値 | `ninlil_status_t` | runtime.h:151 |
| struct_size規約 | out_resultはSTRUCT_HEADER必須 | 12:1602-1612 |
| nullability | runtime, offer_id, out_resultすべてnon-NULL | 12:2425, 2428 |
| 受理条件 | M1aでは常に`NINLIL_E_UNSUPPORTED`。NULL offer_idは先にINVALID_ARGUMENT | 12:2428, 04:285 |
| 状態遷移 | なし (M1a非対応) | 04:147 |
| durable義務 | なし | - |
| error分類 | Validation precedence: INVALID_ARGUMENT (runtime/offer_id/out_result NULL) → ABI_MISMATCH (out_result header不正。runtime opaque、offer_id headerless id128のため対象外) → DEGRADED (execution context zero, docs/12:2394) → WRONG_THREAD → REENTRANT → UNSUPPORTED (M1a常に)。out_result zeroing (INVALID/zero) | 12:2428, 2402, 2394（r5 P1-1反映: precedence順序修正 context-zero→wrong-thread→re-entry） |
| restart后可視性 | N/A | - |
| docs/02接続 | Counter-offer受諾。M1aでは生成/acceptance実装はM2へ | 02:298, 02:459 |
| 利用すべきsrc資産 | なし (stub実装) |  |

### 2.6 ninlil_cancel_request

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_id128_t *transaction_id`, `ninlil_cancel_result_t *out_result` | runtime.h:156-159 |
| 戻り値 | `ninlil_status_t` | runtime.h:156 |
| struct_size規約 | out_resultはSTRUCT_HEADER必須 | 12:1744-1750 |
| nullability | runtime, transaction_id, out_resultすべてnon-NULL | 12:2425 |
| 受理条件 | CONTROLLER roleのみ。local-origin DesiredStateCommandのみ。EventFactはUNSUPPORTED | 12:1817-1823 |
| 状態遷移 | FENCED_BEFORE_DISPATCH / PENDING_REMOTE_FENCE / TOO_LATE_EFFECT_POSSIBLE / ALREADY_TERMINAL。cancel完了ではない | 04:249-254, 12:1838-1847 |
| durable義務 | Local fenceまたはcancel attempt/recordをFULL commit。Targeted management linearization (clock+catch-up) | 12:1807-1813, 1826-1834 |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / UNSUPPORTED / NOT_FOUND / CLOCK_UNCERTAIN / DEGRADED / WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN | 12:1817-1823, 1807-1809（r3 P1-1反映: 「Storage系」→explicit enumeration） |
| restart后可視性 | Persist済みcancel kindはrestart後も同じ値を返す。Cleanup後はNOT_FOUND | 12:1834, 1823 |
| docs/02接続 | DesiredStateCommandのcancel。未実行部分を止めるだけ。既に起きたeffectを元に戻さない | 02:82 |
| 利用すべきsrc資産 | `src/model/deadline_projection.c/.h` (deadline/evidence close判定), `src/model/desired_deadline_transition.c/.h`, `src/model/scheduler_candidate.c/.h` (cancel work kind 13/14) |  |

### 2.7 ninlil_event_resume

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_id128_t *transaction_id`, `const ninlil_event_resume_request_t *request`, `ninlil_event_resume_result_t *out_result` | runtime.h:161-165 |
| 戻り値 | `ninlil_status_t` | runtime.h:161 |
| struct_size規約 | request/resultはSTRUCT_HEADER必須 | 12:1870-1887 |
| nullability | runtime, transaction_id, request, out_resultすべてnon-NULL。request内audit_metadata 1-128 bytes | 12:2425, 1943 |
| 受理条件 | ENDPOINT roleのみ。PARKED_RETRYのEventFactのみ手動再開。COUNTER_EXHAUSTED causeはNOT_RESUMABLE | 12:1938-1940, 1955 |
| 状態遷移 | RESUMED / ALREADY_RESUMED / NOT_PARKED / ALREADY_RELEASED / ALREADY_DISCARDED / NOT_EVENT_FACT / CONFLICT / STALE_SPOOL_REVISION / LIMIT_EXHAUSTED / NOT_RESUMABLE | 12:1852-1862 |
| durable義務 | 成功時retry cycle reset + spool revision incrementを1 FULL commit。Ledger replay resultもpersist | 12:1936, 1943 |
| error分類 | API: INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / UNSUPPORTED / NOT_FOUND / CLOCK_UNCERTAIN / DEGRADED / WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN。Semantic: NINLIL_OK + kind | 12:1938-1958（r2 P1-1反映: Storage status explicit追加） |
| restart后可視性 | Ledger replayはstored canonical resultをexact返却。Storage commit unknown後も0回または1回mutationへ収束 | 12:1943, 1956 |
| docs/02接続 | EventFactのpark再開。fresh availability epochまたはoperator操作で再開 | 02:65 |
| 利用すべきsrc資産 | `src/model/scheduler_candidate.c/.h` (availability consume work kind 2), `src/model/resource_ledger.c/.h` (spool capacity), `src/model/domain_store_codec.c/.h` + `domain_store_body_codec.c/.h` (event record codec) |  |

### 2.8 ninlil_event_discard

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_id128_t *transaction_id`, `const ninlil_event_discard_request_t *request`, `ninlil_event_discard_result_t *out_result` | runtime.h:167-171 |
| 戻り値 | `ninlil_status_t` | runtime.h:167 |
| struct_size規約 | request/resultはSTRUCT_HEADER必須 | 12:1902-1924 |
| nullability | runtime, transaction_id, request, out_resultすべてnon-NULL。request内audit_metadata 1-128 bytes | 12:2425, 1944 |
| 受理条件 | ENDPOINT roleのみ。non-terminal EventFact。expected_event_id/content_digest/spool_revision exact match。acknowledge_required_receipt_absent==1。trusted clock required | 12:1939-1944 |
| 状態遷移 | DISCARDED / ALREADY_DISCARDED / ALREADY_RELEASED / NOT_EVENT_FACT / CONFLICT / STALE_SPOOL_REVISION | 12:1889-1895 |
| durable義務 | event ID, transaction ID, operation, actor, reason, metadata, timestamp, content digest, highest Receipt, retry counters, terminal Outcome, DISCARDED tombstone, payload/spool eraseを1 FULL commit | 12:1945 |
| error分類 | API: INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / UNSUPPORTED / NOT_FOUND / CLOCK_UNCERTAIN / DEGRADED / WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN。Semantic: NINLIL_OK + kind | 12:1939-1958（r2 P1-1反映: Storage系→explicit enumeration） |
| restart后可視性 | Ledger replayはstored canonical resultをexact返却。commit失敗/unknown時はspool解放せず | 12:1947, 1956 |
| docs/02接続 | EventFactの監査付きdiscard。required Receiptまたは明示discardまでactive origin spoolに残す | 02:64 |
| 利用すべきsrc資産 | `src/model/resource_ledger.c/.h` (spool release), `src/model/domain_store_codec.c/.h` + `domain_store_body_codec.c/.h`, `src/model/deadline_projection.c/.h` (audit timestamp) |  |

### 2.9 ninlil_transaction_query

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_id128_t *transaction_id`, `ninlil_transaction_snapshot_t *inout_snapshot` | runtime.h:173-176 |
| 戻り値 | `ninlil_status_t` | runtime.h:173 |
| struct_size規約 | inout_snapshotはSTRUCT_HEADER必須。targets配列はcaller-owned、各要素ABI header初期化必須 | 12:1671-1701, 2426 |
| nullability | runtime, transaction_id, inout_snapshotすべてnon-NULL | 12:2425 |
| 受理条件 | owner thread。callback中可(read-only)。origin-admission domainのみ | 12:2406, 1795 |
| 状態遷移 | なし (read-only) | - |
| durable義務 | なし (read-only) | - |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / DEGRADED (execution context zero) / BUFFER_TOO_SMALL (target_countだけrequired値) / NOT_FOUND | 12:2406, 1803, 2394（r4 P1-1反映: DEGRADED追加） |
| restart后可視性 | admission時にFULL commitしたassurance snapshotをrestart後も同値で返す。retention cleanup済みはNOT_FOUND | 12:1793, 1803 |
| docs/02接続 | Transaction = admission後から終端まで追跡する論理取引。Outcome/Receipt/Observationを別fieldで返す | 02:39, 02:434 |
| 利用すべきsrc資産 | `src/model/domain_store_codec.c/.h` (transaction record decode), `src/model/desired_target_snapshot_internal.c/.h` (target snapshot projection), `src/model/required_receipt_transition.c/.h` (evidence stage) |  |

### 2.10 ninlil_transaction_list

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_query_t *query`, `ninlil_transaction_page_t *inout_page` | runtime.h:178-181 |
| 戻り値 | `ninlil_status_t` | runtime.h:178 |
| struct_size規約 | query/pageはSTRUCT_HEADER必須。items配列各要素ABI header初期化必須 | 12:1717-1737, 1784 |
| nullability | runtime, query, inout_pageすべてnon-NULL。item_capacity==0→items==NULL、>0→non-NULL | 12:1783-1784 |
| 受理条件 | owner thread。callback中可(read-only)。origin-admission domainのみ。family_mask reserved bit検査 | 12:2407, 1795, 1801 |
| 状態遷移 | なし (read-only) | - |
| durable義務 | なし (read-only) | - |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / DEGRADED (execution context zero)。Normal paginationでBUFFER_TOO_SMALLなし | 12:1781, 2407, 2394（r4 P1-1反映: DEGRADED追加） |
| restart后可視性 | transaction_sequenceはrestartを跨いでpersist。pagination中にstateが変わってもsequence不変 | 12:1777-1779 |
| docs/02接続 | Transaction list。queryはObservation, Receipt, Outcomeを別fieldで返す | 02:434 |
| 利用すべきsrc資産 | `src/model/domain_store_codec.c/.h` (summary projection), `src/runtime/domain_store_scanner.c/.h` (prefix iteration) |  |

### 2.11 ninlil_delivery_complete

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_delivery_token_t *token`, `const ninlil_application_result_t *result` | runtime.h:183-186 |
| 戻り値 | `ninlil_status_t` | runtime.h:183 |
| struct_size規約 | token/resultはSTRUCT_HEADER必須 | 12:451-457, 1421-1431 |
| nullability | runtime, token, resultすべてnon-NULL | 12:2425, 1524 |
| 受理条件 | owner thread、callback外。token context/clock epoch non-zero、generation non-zero。result exact combination table適合 | 12:1520-1533, 1489-1510 |
| 状態遷移 | 成功: result cache + token CONSUMED + slot releaseを1 FULL commit。timeout: EXPIRED tombstone | 12:1533, 1518 |
| durable義務 | result cache/Dispositionとtoken invalidationを同じFULL transactionへcommit。commit前にReceipt発行せず | 12:1478, 1533 |
| error分類 | Ordered table: INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / NOT_FOUND / INVALID_STATE / CLOCK_UNCERTAIN / DEGRADED / CAPACITY_EXHAUSTED / WOULD_BLOCK / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN | 12:1520-1543 |
| restart后可視性 | 旧process tokenはactiveへ戻さない。recoveryでRECOVERY_REQUIREDへ収束 | 12:1517, 1547 |
| 応用契約接続（r2 P2-3反映: 列名修正。docs/02/04/12の該当行を明示） | Application resultのdeferred完了。Delivery Disposition/Receiptの発行 | 02:326-350 |
| 利用すべきsrc資産 | `src/model/required_receipt_transition.c/.h` (evidence stage validation), `src/model/resource_ledger.c/.h` (deferred token slot), `src/model/domain_store_codec.c/.h` (result cache record) |  |

### 2.12 ninlil_runtime_step

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `const ninlil_step_budget_t *budget`, `ninlil_step_result_t *out_result` | runtime.h:188-191 |
| 戻り値 | `ninlil_status_t` | runtime.h:188 |
| struct_size規約 | budget/resultはSTRUCT_HEADER必須 | 12:1991-2014 |
| nullability | runtime, budget, out_resultすべてnon-NULL | 12:2425 |
| 受理条件 | owner thread、callback外。budget各field 0は明示値。non-zeroはruntime config上限以下 | 12:2249 |
| 状態遷移 | Stage 1-6: clock → recovery → bearer state → scheduler cut → ring/ingress lanes → health projection | 12:2079-2096 |
| durable義務 | 各micro-operationは規定のFULL commit/hook pairを通る。cursor updateは1 micro-opで最大1回 | 12:2150-2162 |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / REENTRANT / CLOCK_UNCERTAIN / DEGRADED / ENTROPY (attempt entropy) / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN / CAPACITY_EXHAUSTED / WOULD_BLOCK。Normal Bearer/TxGate temporaryはfirst errorではなくclosed reducer input | 12:2081, 2096（r2 P1-1反映: ENTROPY追加、Storage系→explicit enumeration） |
| restart后可視性 | Recovery workをfixed orderで処理。send observation前crashはsame attempt再送。observation後は再送せず | 04:386-394, 12:2164 |
| 応用契約接続（r2 P2-3反映） | callerは`ninlil_runtime_step()`を繰り返し呼ぶ。callbackはstep内だけで実行 | 04:16-17（docs/04典拠。docs/02直接該当なし） |
| 利用すべきsrc資産 | `src/model/scheduler_candidate.c/.h` (ready candidate selection/ordering), `src/model/deadline_projection.c/.h` (timer due判定), `src/model/desired_deadline_transition.c/.h` (Command state transition), `src/model/required_receipt_transition.c/.h` (Receipt reduce), `src/model/resource_ledger.c/.h` + `resource_ledger_batch.c/.h` (capacity block/release), `src/runtime/storage_canonical_plan.c/.h` (canonical plan), `src/runtime/domain_store_scanner.c/.h` (live read/write seam)。**注: d3s1/d3s2/d3s3はruntime_stepの資産ではない（r3 P0-3反映: A1-A4 recovery scan専用）** |  |

### 2.13 ninlil_capacity_snapshot

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `ninlil_capacity_snapshot_t *inout_snapshot` | runtime.h:193-195 |
| 戻り値 | `ninlil_status_t` | runtime.h:193 |
| struct_size規約 | inout_snapshot/entriesはSTRUCT_HEADER必須。全entry_capacity要素のABI header初期化必須 | 12:2043-2048, 2256 |
| nullability | runtime, inout_snapshot non-NULL。entry_capacity==0→entries==NULL、>0→non-NULL | 12:2256 |
| 受理条件 | owner thread。callback中可(read-only) | 12:2410 |
| 状態遷移 | なし (read-only) | - |
| durable義務 | なし (read-only) | - |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / DEGRADED (execution context zero) / BUFFER_TOO_SMALL (required entry_count=11) | 12:2256-2257, 2394（r4 P1-1反映: DEGRADED追加） |
| restart后可視性 | capacity metadataはrestartを跨いでpersist。high_water/epoch/blocked flagもpersist | 12:2188 |
| 応用契約接続（r2 P2-3反映） | Resource accountingの可視化。queue/storage上限時にdeterministic reasonでrejectするための基礎 | 04:396-408（docs/04典拠。docs/02直接該当なし） |
| 利用すべきsrc資産 | `src/model/resource_ledger.c/.h` (capacity metadata read), `src/model/runtime_store_codec.c/.h` (Type 4 capacity decode) |  |

### 2.14 ninlil_metrics_snapshot

| 項目 | 内容 | 典拠 |
|------|------|------|
| 引数 | `ninlil_runtime_t *runtime`, `ninlil_metrics_snapshot_t *out_snapshot` | runtime.h:197-199 |
| 戻り値 | `ninlil_status_t` | runtime.h:197 |
| struct_size規約 | out_snapshotはSTRUCT_HEADER必須 | 12:2050-2074 |
| nullability | runtime, out_snapshot non-NULL | 12:2425 |
| 受理条件 | owner thread。callback中可(read-only) | 12:2411 |
| 状態遷移 | なし (read-only)。自身のcallではcounterを増やさない | 12:2278 |
| durable義務 | なし (read-only) | - |
| error分類 | INVALID_ARGUMENT / ABI_MISMATCH / WRONG_THREAD / DEGRADED (execution context zero) | 12:2411, 2394（r4 P1-1反映: DEGRADED追加） |
| restart后可視性 | Metricsはcreateごとにfresh epoch/zero counter。restart時に旧counterを再構成しない | 12:2260 |
| 応用契約接続（r2 P2-3反映） | Observability。transaction journalの代替ではない | 12:2260（docs/12典拠。docs/02直接該当なし） |
| 利用すべきsrc資産 | `src/model/runtime_lifecycle_model.c/.h` (health projection), `src/model/resource_ledger.c/.h` (counter read) |  |

## 3. docs/02 応用契約との接続点まとめ

| 応用概念 | 接続API | 典拠 |
|----------|---------|------|
| Command (DesiredStateCommand) | submit (sender), service_register (receiver callback), cancel_request, transaction_query/list, delivery_complete (receiver), runtime_step (dispatch/receipt) | 02:67-83 |
| Event (EventFact) | submit (sender), service_register (receiver callback), event_resume, event_discard, transaction_query/list, delivery_complete (receiver), runtime_step (park/resume) | 02:47-65 |
| ApplicationData | submit admission後にRuntime所有。M1aでは独立public C typeなし。Transaction/payload/descriptor snapshotとして保存 | 02:217 |
| ServiceDescriptor | service_register。family/direction/authority/apply/custody/evidence/deadline/rate quota | 02:173-198 |
| Submission → Transaction | submit。admission時にtransaction ID割当。idempotency keyで収束 | 02:200-219 |
| Receipt / Disposition | delivery_complete (receiver application result), runtime_step (Bearer ingress reduce) | 02:326-350 |
| Outcome | transaction_query/list。terminal不変。late evidenceは反転しない | 02:352-379 |
| Backpressure (EventFact) | event_resume/discard。spool満杯は明示failure | 02:385 |
| Backpressure (Command) | cancel_request。supersedeはM1a非対応 | 02:386 |

## 4. 既存実装資産の接続可能性

| src資産 | 接続API | 役割 |
|---------|---------|------|
| `src/model/submission_preflight.c/.h` | submit | syntax/schema/content digest/idempotency key validation |
| `src/model/submission_admission.c/.h` | submit, service_register | admission control, quota, idempotency lookup, family validation |
| `src/model/scheduler_candidate.c/.h` | runtime_step, submit, cancel_request, event_resume | scheduler owner/candidate selection, work kind ordering, availability consume |
| `src/model/runtime_lifecycle_model.c/.h` | runtime_create, runtime_destroy, runtime_step, metrics_snapshot | lifecycle state machine, health projection |
| `src/model/runtime_store_bootstrap.c/.h` | runtime_create | L2a bootstrap: 17-record presence classification, profile compare, identity rotation |
| `src/model/runtime_store_codec.c/.h` | runtime_create, capacity_snapshot, transaction_query | L2a envelope/CRC/Type 1-4 codec |
| `src/model/resource_ledger.c/.h` | submit, runtime_step, delivery_complete, event_resume/discard, capacity_snapshot | capacity reservation/release/block/epoch |
| `src/model/resource_ledger_batch.c/.h` | runtime_step | batch capacity operations (cleanup, retention) |
| `src/model/deadline_projection.c/.h` | runtime_step, cancel_request, transaction_query | deadline/evidence-close timer due判定 |
| `src/model/desired_deadline_transition.c/.h` | runtime_step, cancel_request | Command state transition (expiry, evidence close) |
| `src/model/required_receipt_transition.c/.h` | runtime_step, delivery_complete, transaction_query | Receipt stage transition, evidence validation |
| `src/model/desired_target_snapshot_internal.c/.h` | transaction_query | target snapshot projection |
| `src/model/domain_store_codec.c/.h` | runtime_step, transaction_query/list, event_resume/discard | domain record encode/decode |
| `src/model/domain_store_body_codec.c/.h` | runtime_step, event_resume/discard | domain record body codec |
| `src/model/ncl1_codec.c/.h` | ~~runtime_step~~ **B1スコープ外**（P0-4反映） | NCL1はU4 private control envelope。B1は`ninlil_bearer_ops_t` typed messageを直接使用。後続Bearer provider/U4統合トランチへ |
| `src/model/control_frame_codec.c/.h` | ~~runtime_step~~ **B1スコープ外**（P0-4反映） | control frame wire format。B1スコープ外 |
| `src/runtime/runtime_store_stage5_seam.c/.h` | runtime_create | Stage 5 integration seam |
| `src/runtime/stage5_empty_metadata.c/.h` | runtime_create | empty namespace metadata handling |
| `src/runtime/runtime_store_orchestrator.c/.h` | runtime_create, runtime_destroy | store orchestration layer |
| `src/runtime/storage_canonical_plan.c/.h` | runtime_step | canonical storage plan (begin→final view) |
| `src/runtime/domain_store_d3s1.c/.h` | ~~runtime_step~~ **A1-A4 recovery scan**（r2 P0-3反映） | Stage 5 namespace recovery phase 1。B1-cのlive operation/read-write seamとは独立 |
| `src/runtime/domain_store_d3s2.c/.h` | ~~runtime_step~~ **A1-A4 recovery scan**（r2 P0-3反映） | Stage 5 namespace recovery phase 2。B1-cのlive operation/read-write seamとは独立 |
| `src/runtime/domain_store_d3s3.c/.h` | ~~runtime_step~~ **A1-A4 recovery scan**（r2 P0-3反映） | Stage 5 namespace recovery phase 3。B1-cのlive operation/read-write seamとは独立 |
| `src/runtime/domain_store_scanner.c/.h` | runtime_step, transaction_list | domain store iteration/scan |
| `src/contract/abi_contract.c/.h` | 全API | ABI struct validation, enum domain check |

## 5. 未確定・矛盾・不足の列挙 (B1計画 P0候補)

### 5.1 未確定事項

| # | 事項 | 影響API | 根拠 |
|---|------|---------|------|
| U1 | L2b domain recovery scanのexact実装境界。L2aはpure modelでStorage callを持たず、L2bがStorage open/load/bootstrap/recoveryを担当するが、L2bのbounded Runtime-owned memory region設計が未固定 | runtime_create | 12:1274-1278 |
| U2 | Stage 5のfamily 5/6 (internal-invariant health source / domain record witness) はD1 codec/D2 scanner/D3 validation未完了の間は生成せず、Stage 5や汎用COMMIT_UNKNOWN recoveryを完成扱いしない | runtime_create | 12:1246 |
| U3 | CLOCK_BASELINE (17章 family 6 subtype 62) のD1以降実装が未完了。Stage 7のpure clock mapperはoptional external baselineを受け取るが、production source/update境界は17章正本 | runtime_create | 12:1203, 12:1274 |
| U4 | `ninlil_transaction_query` / `transaction_list` のdomain store read path（`domain_store_scanner`とのexact seam）がdocs/12に明示されていない。d3s phaseとは無関係（r3 P0-3反映: d3sはrecovery scan専用でありquery/list read pathではない）。**注: 実装設計事項でありpublic contract不足ではない（P2-2反映）** | transaction_query, transaction_list | 不明 (docs/12に該当記述なし) |
| U5 | ~~Bearer messageのNCL1 encode/decodeとruntime_step stage 5 ring laneのexact integration point~~ **解消済み（P0-4反映）**: NCL1はU4 private control envelope（`ncl1_codec.h:4`）でありB1スコープ外。B1はpublic `ninlil_bearer_ops_t`のtyped messageを直接使用する（`platform.h:207`）。後続Bearer provider/U4統合トランチへ送る | ~~runtime_step~~ | 解消済み |
| U6 | `ninlil_delivery_complete` のrole固有hook pair (`controller.*` / `endpoint.*`) のexact実装seamがsrc/runtime/のどのmoduleに対応するか。**注: 実装設計事項でありpublic contract不足ではない（P2-2反映）** | delivery_complete | 12:1533 (hook pair名は規定あるがsrc対応は不明) |

### 5.2 矛盾・緊張関係

| # | 事項 | 影響API | 根拠 |
|---|------|---------|------|
| C2 | **解消済み（r2 P0-3反映）**: D3-S群はStage 5 namespace recovery scannerであり（`domain_store_d3s1.h:4`）、scheduler micro-operation分類ではない。ring laneとは無関係。B1-cのlive operationは独立seamで実装する | ~~runtime_step~~ | 解消済み |

### 5.2b Scanner適合確認（r2 P2-1反映: C1を「矛盾」から分離）

| # | 事項 | 影響API | 根拠 |
|---|------|---------|------|
| C1 | docs/04:299と12:2406/12:1783の規則に矛盾はない（本文自身が「矛盾はない」と結論）。listのitem_capacity==0時のhas_more判定read snapshot範囲が12:1783にあり、d3s scannerの実装がこれに適合するか未検証。**分類: scanner適合確認（矛盾ではない）** | transaction_query, transaction_list, capacity_snapshot | 04:299, 12:2406, 12:1783 |

### 5.3 不足・欠落

| # | 事項 | 影響API | 根拠 |
|---|------|---------|------|
| G1 | `ninlil_runtime_destroy`のactive token group recovery (operation kind 19) を担当するsrc moduleが不明。`runtime_lifecycle_model`がlifecycle state machineを持つが、destroy pathのdurable token invalidation group commitの実装場所が未確定。**注: 実装設計事項でありpublic contract不足ではない（P2-2反映）** | runtime_destroy | 12:2417, src/内にdestroy専用moduleなし |
| G2 | `ninlil_offer_accept`はM1a stub (`NINLIL_E_UNSUPPORTED`) だが、validation precedence (NULL offer_id → INVALID_ARGUMENT、well-formed → UNSUPPORTED) のexact実装が`abi_contract`に含まれるか不明 | offer_accept | 12:2428 |
| G3 | `ninlil_event_resume` / `ninlil_event_discard` のmanagement request digest (SHA-256) 計算がsrc/内のどのmoduleに実装されるか不明。`domain_store_body_codec`がcandidateだが、exact digest format (12:1970-1986) の実装場所が未確定。**注: 実装設計事項でありpublic contract不足ではない（P2-2反映）** | event_resume, event_discard | 12:1970-1986 |
| G4 | `ninlil_submit`のcanonical submission digest計算 (SHA-256) のexact実装場所が不明。**rev2修正（P0-9反映）**: exact byte layoutはdocs/14:1970に存在する（canonical-submission-v1）。rev1で「不明」としたのは監査対象からdocs/14を落としていたため。実装moduleの配置はdocs/workで決定可。normative semanticの追加・変更はcanonical doc/vectorへfreeze | submit | 14:1970, 12:2148, 12:1637 |
| G5 | `ninlil_runtime_step`のhealth projection (12:2280-2314) の8-slot closed multiset実装が`runtime_lifecycle_model`に含まれるか、別moduleが必要か不明。**注: 実装設計事項でありpublic contract不足ではない（P2-2反映）** | runtime_step, metrics_snapshot | 12:2282-2314 |
| G6 | **解消済み（P0-4反映）**: `src/transport/` (control_session, logical_session, byte_stream) はB1スコープ外。B1はpublic `ninlil_bearer_ops_t`のtyped messageを直接使用する（`platform.h:207`）。control_session/logical_sessionは後続Bearer provider/U4統合トランチへ送る | ~~runtime_step~~ | 解消済み |

## 6. B1実装で最もリスクの高い上位5論点

### Risk 1: runtime_create Stage 5 recovery + L2b seam (U1, U2, U3)

**影響**: runtime_create, runtime_destroy, runtime_step (recovery work)
**理由**: Stage 5は17-record bootstrap、profile binding、counter/capacity相互validation、durable health-source scan、identity rotation、cleanup/status mappingを担当するが、L2bのbounded memory region設計が未固定 (12:1278)。family 5/6未生成のためStage 5完成扱いできない (12:1246)。CLOCK_BASELINEの17章実装も未完了 (12:1203)。これが未完成だと全APIのrestart后可視性保証が成立しない。

### Risk 2: runtime_step scheduler ring + live operation seam（r2 P0-3反映: 修正済み）

**影響**: runtime_step (全micro-operation)
**理由**: 22種のwork kind、ring/ingress lane交互処理、cursor commit placement、budget preflightのexact実装が、scheduler_candidate pure modelとruntime bodyのlive read-write seamで最も複雑。trace determinism (12:2088) とcrash recovery (12:2164) の両方を満たす必要がある。注: d3s1/d3s2/d3s3はStage 5 recovery scannerであり（`domain_store_d3s1.h:4`）、B1-cのlive operationとは無関係。A1-A4のrecovery bindが使用。

### Risk 3: delivery_complete + callback lifecycle (U6, G5)

**影響**: delivery_complete, runtime_step (callback dispatch)
**理由**: 7.2のordered validation table (12:1520-1543) は13段階のprecedenceを持ち、role固有hook pair、token lifecycle (ACTIVE→CONSUMED/EXPIRED/RECOVERY_REQUIRED_TOMBSTONE)、DELIVERY_STARTED pre-commit、result cache commitのexact atomicityが要求される。callback FATAL/contract violationのrecovery commit (12:1482-1485) とhealth 8-slot projection (12:2282-2314) の実装seamが未確定。

### Risk 4: submit admission atomicity + idempotency (G4)

**影響**: submit
**理由**: 全familyの新規admission exact order (12:1032) は11段階のstrict sequenceを持ち、EventFactはprovider call、Core quota、grant prospective limit、transaction ID draw、1 FULL admission commitのall-or-noneが要求される。canonical submission digest (14章) とidempotency mapping (key mapping + event mappingの二重lookup, 12:1624-1629) のexact実装が未確認。conflict時の決定的existing transaction ID返却規則 (12:1628) も複雑。

### Risk 5: event_resume/discard management ledger + linearization (G3)

**影響**: event_resume, event_discard
**理由**: Targeted management linearization (12:1807-1813) はclock取得→catch-up→management inputの順で、same-time priority (13章) との相互作用が複雑。Ledger replay/conflict (12:1950-1958) はoperation ID/digest/spool revisionの3軸で、8 resume + 1 discardのfixed capacity slot管理、management request digest (12:1970-1986) のexact SHA-256計算、availability epoch consume (12:1936) との整合性が必要。COUNTER_EXHAUSTED時のNOT_RESUMABLE absorbing state (12:1930-1931) もedge caseが多い。

---

## 7. 14 API網羅確認

| # | API | §2表 | §3接続 | §4資産 | §5課題 |
|---|-----|------|--------|--------|--------|
| 1 | runtime_create | 2.1 | ○ | ○ | U1,U2,U3 |
| 2 | runtime_destroy | 2.2 | ○ | ○ | G1 |
| 3 | service_register | 2.3 | ○ | ○ | - |
| 4 | submit | 2.4 | ○ | ○ | G4 |
| 5 | offer_accept | 2.5 | ○ | ○ | G2 |
| 6 | cancel_request | 2.6 | ○ | ○ | - |
| 7 | event_resume | 2.7 | ○ | ○ | G3 |
| 8 | event_discard | 2.8 | ○ | ○ | G3 |
| 9 | transaction_query | 2.9 | ○ | ○ | U4 |
| 10 | transaction_list | 2.10 | ○ | ○ | U4,C1 |
| 11 | delivery_complete | 2.11 | ○ | ○ | U6 |
| 12 | runtime_step | 2.12 | ○ | ○ | C2,U5,G5 |
| 13 | capacity_snapshot | 2.13 | ○ | ○ | C1 |
| 14 | metrics_snapshot | 2.14 | ○ | ○ | G5 |

全14 API網羅済み。

---

## 8. 監査修正履歴

### rev2（Sol high r1レビュー反映）

| 所見ID | 修正内容 |
|--------|----------|
| P0-4 | §4 ncl1_codec/control_frame_codecをB1スコープ外へ。§5 U5/G6を解消済みへ |
| P0-9 | §0にdocs/13/14/17委譲正本追加。§5 G4をdocs/14:1970参照へ修正 |
| P1-1 | §2.1 create error分類にCONFLICT追加。§2.3 registerにWRONG_THREAD/REENTRANT追加。§2.4 submitにStorage/Port status追加。§2.12 stepにgeneric ABI/thread/re-entry/Storage status追加 |
| P1-2 | §2.5 offer_accept error分類をfull validation precedenceへ修正 |
| P2-1 | §5.2 C1を「矛盾」→「scanner適合確認」へ再分類 |
| P2-2 | §5.1 U4/U6、§5.3 G1/G3/G5に「実装設計事項」注記追加 |
| P2-3 | §2.11/§2.12/§2.13/§2.14のdocs/02接続列の典拠混在を修正 |

### rev3（Sol high r2レビュー反映）

| 所見ID | 修正内容 |
|--------|----------|
| P0-3 | §4 d3s1/d3s2/d3s3を「A1-A4 recovery scan」へ修正（B1-c編集資産から除外）。§6 Risk 2を修正 |
| P1-1 | §2.1 createからWRONG_THREAD/REENTRANT削除（runtime生成前callのため対象外）。§2.3 registerにDEGRADED/WOULD_BLOCK追加。§2.7 event_resumeにStorage status explicit追加。§2.8 event_discardの「Storage系」→explicit enumeration。§2.12 stepにENTROPY追加 |
| P2-1 | §5.2からC1を完全分離し§5.2b「Scanner適合確認」節へ移動 |
| P2-3 | §2.11/§2.12/§2.13/§2.14の列名を「応用契約接続」へ修正。delivery行のTBD削除（02:326-350で確定） |

### rev4（Sol high r3レビュー反映）

| 所見ID | 修正内容 |
|--------|----------|
| P0-3 | §2.12 runtime_step「利用すべきsrc資産」からd3s1/d3s2/d3s3を完全削除。「A1-A4 recovery scan専用」注記追加。§5.1 U4からd3s参照を削除し「domain_store_scannerとのseam」へ修正 |
| P1-1 | §2.6 cancel_request error分類の「Storage系」→「WOULD_BLOCK / CAPACITY_EXHAUSTED / STORAGE / STORAGE_CORRUPT / STORAGE_COMMIT_UNKNOWN」へexplicit展開 |

### rev5（Sol high r4レビュー反映）

| 所見ID | 修正内容 |
|--------|----------|
| P1-1 | §2.2 destroy、§2.5 offer_accept、§2.9 query、§2.10 list、§2.13 capacity、§2.14 metricsのerror分類にDEGRADED (execution context zero, docs/12:2394)追加。§2.5 offer_acceptのABI_MISMATCH対象をout_result headerのみに修正（runtime opaque、offer_id headerless） |

### rev6（Sol high r5レビュー反映）

| 所見ID | 修正内容 |
|--------|----------|
| P1-1 | §2.5 offer_accept precedence順序を修正: outer validation→DEGRADED (context-zero)→WRONG_THREAD→REENTRANT→UNSUPPORTED（docs/12:2394正本） |
