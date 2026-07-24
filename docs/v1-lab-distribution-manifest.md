# Ninlil V1 LAB distribution manifest

状態: V1 LAB RC1 packaging 正本（タグ `v1.0-lab-rc1`）

本 manifest は **Ninlil V1 LAB** の配布物一覧です。production 認定・SBOM・release
signing は含みません（V2）。

## 1. ソース repository（開発・検証）

| 区分 | パス / 成果物 |
| --- | --- |
| Public ABI headers | `include/ninlil/*.h` |
| Private runtime（非 export） | `src/runtime/`, `src/model/`, `src/transport/`, `src/radio/` |
| POSIX SQLite port | `ports/posix/`, `ports/posix/include/ninlil_posix_sqlite_storage.h` |
| ESP-IDF component | `ports/esp-idf/` |
| Host LAB platform | `ports/posix/lab_platform/`, loopback bearer |
| Tests + gates | `tests/`, `tools/*_gate.py`, `cmake/*_ctest.cmake` |
| V1 LAB 計画・証拠 | `docs/work/2026-07-23-*.md` |
| Examples | `examples/v1_lab/` |
| License | `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md` |

## 2. Installable host CMake package（consumer smoke 対象）

`cmake --install` により以下を export します（SQLite3 発見時）:

| 成果物 | 配置 |
| --- | --- |
| `Ninlil::ninlil` INTERFACE | `lib/cmake/Ninlil/` |
| `Ninlil::ninlil_posix_sqlite_storage` STATIC | `lib/libninlil_posix_sqlite_storage.a` |
| Public headers | `include/ninlil/`, `include/ninlil_posix_sqlite_storage.h` |
| License | `share/licenses/ninlil/LICENSE` |

**非 export（V1 LAB）:** `ninlil_runtime_private`, R7 Host crypto, C4/C5/C6 LAB
private archives, test fixtures, examples バイナリ（build tree のみ）。

## 3. Host 実行物（build tree; CI / ローカル検証）

| 区分 | 代表 target / CTest |
| --- | --- |
| 統合 E2E gate | `ninlil_v1_integration_gate_e2e_test`, `v1_integration_gate_*` |
| V1 LAB examples | `ninlil_v1_lab_*_example` |
| Consumer install smoke | `posix_sqlite_storage_installed_consumer` |
| 再現 script | `tools/v1_lab_consumer_smoke.sh` |

## 4. ESP-IDF target（compile smoke）

| 成果物 | 検証 |
| --- | --- |
| `ports/esp-idf/components/ninlil` | `.github/workflows/esp-idf.yml`, `esp_idf_component_packaging_gate` |

## 5. V1 LAB で主張しないもの

- SBOM / release signing / production 法規認定
- 物理 USB / RF / flash / power-cut / Display・Leak node HIL E2E
  （`docs/work/2026-07-23-v1-rc-residuals.md` 参照）
