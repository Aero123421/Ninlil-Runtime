# V1-LAB unit 1b 実行証拠

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
一時build: `tmp-v1`  
前提: unit 1a（`v1_durable_allowlist` + writer/recovery gate）commit 済み

## A. POSIX SQLite 完成昇格

| 項目 | 実装 |
| --- | --- |
| factory/ownership/shutdown | `ninlil_posix_sqlite_storage_create` / `destroy`、inode-keyed flock sidecar、`simulate_crash` |
| 再 open | `tests/port/posix_sqlite_storage_test.c` `test_restart_and_crash_recovery` / `test_sigkill_dead_owner_reopen` + restart E2E |
| fault conformance | write/commit/短い read/破損 page — `posix_sqlite_storage` CTest（interpose 含む） |
| allowlist 結線 | `stage5_empty_metadata.c` `put_encoded` → `ninlil_v1_durable_storage_put`（gate + put 単一路） |
| restart recovery | `src/runtime/v1_durable_restart.c` `ninlil_v1_durable_restart_recovery` + `ninlil_v1_durable_recovery_publication_gate_storage` |

README: `ports/posix/sqlite_storage/README.md`（V1-LAB complete 表記）

## B. restart E2E（単一 process）

`tests/runtime/v1_posix_sqlite_restart_e2e_test.c` / CTest `v1_posix_sqlite_restart_e2e`

| 負例/正常 | テスト | 期待動作 |
| --- | --- | --- |
| (a) 正常 restart | `test_normal_restart_resume_no_duplicate` | bootstrap+metadata→provider shutdown/reopen→`storage_recovery_complete=1`、metadata 再 commit は `wrote_metadata=0`（重複なし） |
| (b) COMMIT_UNKNOWN | `test_commit_unknown_restart_reject` | `commit_unknown_active=1` → `reject_reason=COMMIT_UNKNOWN`、`success_evidence_count=0`、誤 success なし |
| (c) 破損 DB page | `test_corrupt_page_recovery_reject` | header 破損→reopen 失敗または recovery 非 OK、`storage_recovery_complete=0`、bounded termination |
| (d) allowlist 外注入 | `test_allowlist_external_injection_reject` | future key 注入→`publication_gate_storage` が MIXED/UNKNOWN 拒否、recovery `success_evidence_count=0` |

## C. negative 4 種 RED→期待動作（1a gate + 1b E2E）

| 種別 | RED プローブ | 1b 期待 |
| --- | --- | --- |
| unknown | `v1_durable_allowlist_test` `test_recovery_reject_unknown` | gate `UNKNOWN`、evidence 0 |
| corrupt | `test_recovery_reject_corrupt` | gate `CORRUPT`、evidence 0 |
| mixed | `test_recovery_reject_mixed` | gate `MIXED`、evidence 0 |
| COMMIT_UNKNOWN | `test_recovery_reject_commit_unknown_restart` + E2E (b) | gate `COMMIT_UNKNOWN`、evidence 0 |

## D. 実行コマンド / 結果

```bash
cd tmp-v1
cmake .. -DNINLIL_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j8
ctest
```

結果（2026-07-23 実行）:

```
100% tests passed, 0 tests failed out of 230
Total Test time (real) = 246.61 sec
```

unit 1b 関連:

| CTest | 結果 |
| --- | --- |
| posix_sqlite_storage | Passed |
| posix_sqlite_storage_shared_conformance | Passed |
| v1_posix_sqlite_restart_e2e | Passed |
| v1_durable_allowlist | Passed |
| v1_durable_allowlist_source_gate | Passed |
| v1_durable_allowlist_gate_self_test | Passed |
| stage5_empty_metadata | Passed |
| runtime_private_subproject_smoke | Passed |

```bash
ctest -N | tail -1
# Total Tests: 230
```

## E. stub/TODO 0（grep）

```bash
rg -i 'TODO|FIXME|stub' \
  src/runtime/v1_durable_restart.* \
  src/runtime/v1_durable_allowlist.* \
  tests/runtime/v1_posix_sqlite_restart_e2e_test.c \
  ports/posix/sqlite_storage/ninlil_posix_sqlite_storage.c
```

結果: 0 件

RC=0
