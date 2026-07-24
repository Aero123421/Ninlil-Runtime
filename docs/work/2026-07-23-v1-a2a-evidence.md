# V1-LAB unit 2a 実行証拠（B1 public Runtime spine）

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
一時build: `tmp-v1`  
正本: [2026-07-21-b1-runtime-body-plan-draft.md](2026-07-21-b1-runtime-body-plan-draft.md)（B1-a/b/c 受理段）、[2026-07-23-ninlil-v1-lab-plan.md](2026-07-23-ninlil-v1-lab-plan.md) 項目 2

## A. 2a スコープ実装

| 領域 | 実装 | 備考 |
| --- | --- | --- |
| `runtime_create` / `runtime_destroy` | `src/runtime/runtime_public.c` | Stage 1–9 + resource ledger init |
| `service_register` | 同上 + `runtime_v1_spine_durable.c` | 重複契約は `CONFLICT`、上限は `CAPACITY_EXHAUSTED` |
| `service_deregister` | destroy 内 `service_deregister_slot()` のみ | public API なし（B1 計画どおり） |
| `submit` admission | `runtime_v1_spine_durable.c` + model preflight/admission | canonical digest → preflight → id alloc → allowlist marker durable put |
| `cancel_request` admission | 同上 | `FENCED_BEFORE_DISPATCH`（pending_dispatch 時） |
| `runtime_step` spine | `runtime_public.c` | bounded budget、再入禁止、fail-closed |
| canonical submission digest | `src/runtime/submission_canonical_v1.c` | docs/14 §Canonical Submission Encoding v1 |
| spine durable markers | allowlist kinds 20–22 / ops 4–6 | owner S1；domain TRANSACTION row は 2b |

## B. API × テスト対応（`v1_runtime_spine`）

| Public API | 正常系 | 負例（期待 status / 意味） |
| --- | --- | --- |
| `ninlil_runtime_create` | `test_create_destroy_happy` | `test_create_null_invalid` → `INVALID_ARGUMENT` |
| `ninlil_runtime_destroy` | `test_create_destroy_happy` | `test_destroy_null_invalid` → `INVALID_ARGUMENT` |
| `ninlil_service_register` | `test_register_submit_cancel_step_happy`, `test_register_exact_reattach` | `test_register_null_invalid`（NULL 各引数）→ `INVALID_ARGUMENT`；`test_register_capacity_exhausted` → `CAPACITY_EXHAUSTED` |
| `ninlil_submit` | `test_register_submit_cancel_step_happy`（`ADMITTED_READY`） | `test_submit_null_invalid` → `INVALID_ARGUMENT` |
| `ninlil_cancel_request` | `test_register_submit_cancel_step_happy`（`FENCED_BEFORE_DISPATCH`） | `test_cancel_not_found` → `NOT_FOUND`；`test_cancel_wrong_role` → `UNSUPPORTED`；`test_cancel_zero_txn_invalid` → `INVALID_ARGUMENT` |
| `ninlil_runtime_step` | `test_register_submit_cancel_step_happy` | `test_wrong_thread` → `WRONG_THREAD` |
| 2a 範囲外 API | — | `test_offer_accept_unsupported` → `UNSUPPORTED`（false success 0） |

## C. CTest（ASan/UBSan build）

```bash
cd tmp-v1
cmake .. -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . --target ninlil_v1_runtime_spine_test ninlil_v1_durable_allowlist_test
ctest -R "v1_runtime_spine|v1_durable_allowlist" --output-on-failure
```

`ctest -N`（関連）:

```
  Test  #31: v1_durable_allowlist
  Test  #32: v1_runtime_spine
  Test  #73: v1_durable_allowlist_source_gate
  Test  #74: v1_durable_allowlist_gate_self_test
```

実行結果（2026-07-23）:

| CTest | 結果 |
| --- | --- |
| v1_runtime_spine | Passed |
| v1_durable_allowlist | Passed |
| v1_durable_allowlist_source_gate | Passed |
| v1_durable_allowlist_gate_self_test | Passed |

直接実行:

```
./ninlil_v1_runtime_spine_test  → RC=0
```

## D. 負例サマリ（false success 0）

| ケース | 観測 |
| --- | --- |
| NULL runtime / service / submission / result | API status `INVALID_ARGUMENT`、result kind 未設定 |
| service 上限超過 | `CAPACITY_EXHAUSTED`、2 件目 register 失敗 |
| cancel 未知 txn | `NOT_FOUND` |
| cancel endpoint role | `UNSUPPORTED` |
| step 別スレッド context | `WRONG_THREAD` |
| zero transaction_id cancel | `INVALID_ARGUMENT` |

## E. allowlist 拡張（unit 2a）

正本更新: [2026-07-23-v1-durable-allowlist.md](2026-07-23-v1-durable-allowlist.md) §2a  
コード: `NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT = 22`、`OPERATION_COUNT = 6`

## F. B1 計画との差分（理由）

| 項目 | 計画 | 2a 実装 | 理由 |
| --- | --- | --- | --- |
| submit durable body | domain TRANSACTION anchor 等 | spine marker row（`SPINE_TXN_ADMISSION`）のみ | 2a = admission enqueue まで；深部 domain write set は 2b |
| `runtime_step` work kinds | 22 kind 完全消化 | spine（clock / re-entry / budget / `pending_dispatch` フラグ） | 2a 受理；delivery/durable 深部は 2b |
| canonical golden vector 専用 CTest | B1-b P1-4 独立 golden | encoder 実装 + spine 統合テストで digest 経路検証 | 2a 最小受理；専用 golden CTest は follow-up 可 |
| `service_deregister` public | 計画に内部 deregister 記載 | destroy 経路のみ | public ABI 変更禁止 |

## G. stub/TODO grep（2a 対象）

```bash
rg -i 'TODO|FIXME|\bstub\b' \
  src/runtime/runtime_public.c \
  src/runtime/runtime_v1_spine_durable.c \
  src/runtime/submission_canonical_v1.c \
  src/runtime/v1_durable_allowlist.c \
  tests/runtime/v1_runtime_spine_test.c
```

結果: 0 件（テスト fixture の `origin_stub` コールバック名のみ — 未実装 API stub ではない）

RC=0
