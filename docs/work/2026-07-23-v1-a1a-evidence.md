# V1-LAB unit 1a 実行証拠

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
一時build: `tmp-v1`  
正本: [2026-07-23-v1-durable-allowlist.md](2026-07-23-v1-durable-allowlist.md)

## A. Allowlist 文書 + 実測差分表

- 正本: `docs/work/2026-07-23-v1-durable-allowlist.md`
- コード表: `src/runtime/v1_durable_allowlist.c` `g_ninlil_v1_durable_allowlist_table[]`（19 kinds）
- 実測差分: 現行 Stage5 writer は bootstrap-17 + metadata-16 + clock TRUSTED 更新のみ生成。Family 6 business subtypes（SERVICE/TRANSACTION/DELIVERY/BLOB/…）は allowlist 外・writer 未接続（§7.3 参照）

## B. Writer gate RED プローブ

`tests/runtime/v1_durable_allowlist_test.c` `test_writer_gate_red_probe`:

- `METADATA_INIT_COMMIT` + `RS_BINDING` key → `NINLIL_E_UNSUPPORTED`（put 0）
- `ninlil_v1_durable_probe_disallowed_writer_kind` → `NINLIL_E_UNSUPPORTED`
- 構造 gate mutation: `tools/v1_durable_allowlist_gate.py self-test`（gate bypass → RED）

Writer 経路:

- `runtime_store_orchestrator.c` `commit_new_bootstrap`: `ninlil_v1_durable_writer_gate_check(BOOTSTRAP_COMMIT, …)`
- `stage5_empty_metadata.c` `put_encoded`: gate → `storage->put`（1 箇所のみ）

## C. Recovery 拒否負例 4 種 green

| 負例 | テスト | 結果 |
| --- | --- | --- |
| unknown | `test_recovery_reject_unknown` | `reject_reason=UNKNOWN`, `success_evidence_count=0` |
| corrupt | `test_recovery_reject_corrupt` | `reject_reason=CORRUPT`, `success_evidence_count=0` |
| mixed | `test_recovery_reject_mixed` | `reject_reason=MIXED`, `success_evidence_count=0` |
| COMMIT_UNKNOWN restart | `test_recovery_reject_commit_unknown_restart` | `reject_reason=COMMIT_UNKNOWN`, `adopted=0`, 誤 success なし |

API: `ninlil_v1_durable_recovery_publication_gate()`

## D. 既存 CTest 全 green（ASan/UBSan）

```bash
cd tmp-v1
cmake .. -DNINLIL_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j8
ctest
```

結果（2026-07-23 実行）:

```
100% tests passed, 0 tests failed out of 229
Total Test time (real) = 248.28 sec
```

unit 1a 関連:

| CTest | 結果 |
| --- | --- |
| v1_durable_allowlist | Passed |
| v1_durable_allowlist_source_gate | Passed |
| v1_durable_allowlist_gate_self_test | Passed |
| stage5_empty_metadata | Passed |
| runtime_store_orchestrator | Passed |
| storage_canonical_plan | Passed |
| runtime_store_stage5_seam | Passed |

## E. stub/TODO 0（grep）

```bash
rg -i 'TODO|FIXME|stub' src/runtime/v1_durable_allowlist.* tests/runtime/v1_durable_allowlist_test.c tools/v1_durable_allowlist_gate.py
```

結果: 0 件

RC=0
