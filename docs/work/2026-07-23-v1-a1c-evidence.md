# V1-LAB unit 1c 実行証拠

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
一時build: `tmp-v1`  
前提: unit 1a/1b commit 済み  
規範: `docs/26-u6-transport-custody.md` §9.4 / `docs/21-m3-esp-idf-durable-storage.md` §7

## A. ESP no-success 構造 gate

| 項目 | 実装 |
| --- | --- |
| source gate | `tools/v1_esp_durable_success_gate.py`（ESP_PLATFORM FULL → `COMMIT_UNKNOWN` tail、`flash_bind` = `FULL_ESP_UNPROVEN`、負例テスト存在） |
| target archive gate | 同 script `--archive PATH --archive-kind target`（host-only seam / simulate 禁止） |
| 既存 public API gate | `tools/esp_storage_public_api_gate.py`（visibility + HOST_MODEL compile-exclude） |
| CTest | `v1_esp_durable_success_source_gate` / `v1_esp_durable_success_gate_self_test` |

```bash
python3 tools/v1_esp_durable_success_gate.py check
# ok v1_esp_durable_success_source_gate

python3 tools/v1_esp_durable_success_gate.py self-test
# ok v1_esp_durable_success_gate_self_test
```

## B. readback 一致でも success へ昇格しない負例

`tests/port/esp_storage_conformance_test.c` `test_esp_unproven_readback_match_no_success_promotion`:

- `FULL_ESP_UNPROVEN` で commit → `NINLIL_STORAGE_COMMIT_UNKNOWN`
- cold reinit 後 get → value 一致
- 再 commit FULL → 再び `COMMIT_UNKNOWN`、`full_ok_count == 0`

CTest: `esp_storage_dual_slot_conformance` Passed

## C. ESP provider matrix（P1-2）

正本: `docs/work/2026-07-23-v1-esp-provider-matrix.md`

| Provider | Status |
| --- | --- |
| allocator / bearer / origin_authorization | LAB unavailable fail-closed |
| execution / clock / entropy / tx_gate | implemented |
| storage | implemented（FULL OK 禁止; HIL なし） |

LAB unavailable 実証: `tests/port/v1_esp_provider_availability_test.c`

- `ninlil_esp_idf_provider_admission_request` → `NINLIL_PORT_PERMANENT_FAILURE`（ops 有無問わず）
- `ninlil_esp_idf_platform_ops_admit` → bearer 非 NULL wiring 拒否

CTest: `v1_esp_provider_availability` Passed

## D. ビルド / CTest

```bash
cd tmp-v1
cmake .. -DNINLIL_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build . -j8
ctest
```

結果（2026-07-23 実行）:

```
100% tests passed, 0 tests failed out of 233
Total Test time (real) = 255.77 sec
```

unit 1c 関連:

| CTest | 結果 |
| --- | --- |
| esp_storage_dual_slot_conformance | Passed |
| v1_esp_durable_success_source_gate | Passed |
| v1_esp_durable_success_gate_self_test | Passed |
| v1_esp_provider_availability | Passed |
| esp_storage_public_api_gate | Passed |
| esp_storage_map_gate | Passed |
| esp_idf_component_packaging_gate | Passed |

```bash
ctest -N | tail -1
# Total Tests: 233
```

## E. ESP-IDF target build

ローカル: `docker` daemon 未起動のため `espressif/idf:v5.5.3` target build は未実行。  
CI 相当コマンド正本: `.github/workflows/esp-idf.yml`（`idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build` + `hil_app` + map/public API gate）。

ホスト側 placement gate:

```bash
python3 tools/esp_storage_map_gate.py
# esp_storage_map_gate OK: smoke/sdkconfig placement rules ...
```

## F. stub/TODO 0（grep）

```bash
rg -i '\bTODO\b|\bFIXME\b|\bstub\b' \
  tools/v1_esp_durable_success_gate.py \
  ports/esp-idf/src/platform_availability_logic.* \
  ports/esp-idf/include/ninlil_esp_idf/platform_availability.h
```

結果: 0 件（テスト fixture 名 `g_stub_*` は負例用 ops 構造体であり production stub ではない）

RC=0
