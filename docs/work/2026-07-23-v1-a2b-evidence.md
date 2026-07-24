# V1-LAB unit 2b 実行証拠（B1 durable delivery path）

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
一時build: `tmp-v1`（`-DNINLIL_ENABLE_SANITIZERS=ON`）  
前提: unit 2a commit `d5c8aaa`  
正本: [2026-07-21-b1-runtime-body-plan-draft.md](2026-07-21-b1-runtime-body-plan-draft.md)、[2026-07-23-ninlil-v1-lab-plan.md](2026-07-23-ninlil-v1-lab-plan.md) 項目 2

## A. 2b スコープ実装

| 領域 | 実装 | 備考 |
| --- | --- | --- |
| durable delivery path | `runtime_v1_delivery_durable.c` | queue→callback→evidence→outcome、at-least-once / evidence dedup、callback 失敗時は evidence 成功を書かない |
| `event_resume` / `event_discard` | `runtime_v1_event_mgmt.c` + `runtime_public.c` | PARKED event の再開/破棄、durable ES/ER/ED marker |
| timeout/retry spine | `runtime_v1_delivery_durable.c` | deadline 超過 park、retry budget、`RT` marker（項目 4 本格 policy 前の最小 hook） |
| restart 整合 | `ninlil_rt_v1_delivery_restart_scan()` | TX 先行 2-pass scan；domain scanner は allowlisted spine marker を lex skip |
| allowlist / publication | `v1_durable_allowlist.c` | kinds 23–29 / ops 7–13；publication gate + Stage5 scan 受理 |
| 結線 | `runtime_public.c` | `runtime_step` delivery、`event_resume`/`discard`、`create` 時 restart scan |

## B. API × テスト対応（`v1_runtime_delivery`）

| Public API | 正常系 | 負例（期待 status / result kind） |
| --- | --- | --- |
| `ninlil_runtime_step`（DesiredState delivery） | `test_desired_state_delivery_happy` | — |
| `ninlil_runtime_step` + callback 失敗 | `test_callback_failure_no_false_success` | callback `FATAL` → evidence 成功 marker なし（`g_delivery_calls==1`） |
| `ninlil_event_resume` | `test_callback_failure_no_false_success`, `test_event_resume_discard_flow` | `test_event_resume_wrong_role` → `UNSUPPORTED` |
| `ninlil_event_discard` | `test_event_discard_stale_revision` → `EVENT_DISCARD_STALE_SPOOL_REVISION` | `test_event_discard_invalid_ack` → `INVALID_ARGUMENT` |
| restart + dedup | `test_event_resume_discard_flow`（destroy→recreate 後 `g_delivery_calls` 不増） | — |
| endpoint EventFact park | `test_endpoint_submit_parks` | — |

## C. restart 整合（2a/2b durable record）

| 手順 | 観測 |
| --- | --- |
| controller bootstrap → destroy → seed `TX`+`ES`（PARKED）→ recreate | `env_create` 成功（Stage5 scan + publication gate） |
| `delivery_restart_scan` | TX スロット復元 + ES で `PARKED` / `spool_revision` 一致 |
| delivery 後 destroy→recreate | `test_event_resume_discard_flow` で callback 重複呼び出しなし（evidence 由来 dedup） |
| unit 1b E2E | `v1_posix_sqlite_restart_e2e` Passed（既存 restart 経路との共存） |

## D. CTest（ASan/UBSan build）

```bash
cd tmp-v1
cmake .. -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j8
ctest -R "v1_runtime_delivery|v1_runtime_spine|v1_durable_allowlist|v1_posix_sqlite_restart|runtime_private_subproject" --output-on-failure
```

`ctest -N`（関連）:

```
  Test  #31: v1_durable_allowlist
  Test  #32: v1_runtime_spine
  Test  #33: v1_runtime_delivery
  Test  #74: v1_durable_allowlist_source_gate
  Test  #75: v1_durable_allowlist_gate_self_test
  Test #185: v1_posix_sqlite_restart_e2e
  Test   #1: runtime_private_subproject_smoke
```

実行結果（2026-07-23）:

| CTest | 結果 |
| --- | --- |
| v1_runtime_delivery | Passed |
| v1_runtime_spine | Passed |
| v1_durable_allowlist | Passed |
| v1_durable_allowlist_source_gate | Passed |
| v1_durable_allowlist_gate_self_test | Passed |
| v1_posix_sqlite_restart_e2e | Passed |
| runtime_private_subproject_smoke | Passed |

直接実行:

```
./ninlil_v1_runtime_delivery_test  → RC=0
```

## E. allowlist 拡張（unit 2b）

正本更新: [2026-07-23-v1-durable-allowlist.md](2026-07-23-v1-durable-allowlist.md) §2b  
コード: `NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT = 29`、`OPERATION_COUNT = 13`

## F. stub/TODO grep（2b 対象）

```bash
rg -i 'TODO|FIXME|\bstub\b' \
  src/runtime/runtime_v1_delivery_durable.c \
  src/runtime/runtime_v1_event_mgmt.c \
  src/runtime/runtime_public.c \
  src/runtime/domain_store_scanner.c \
  tests/runtime/v1_runtime_delivery_test.c
```

結果: 0 件

RC=0
