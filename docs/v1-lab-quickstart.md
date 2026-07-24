# Ninlil V1 LAB — Quickstart

状態: V1 LAB RC2 利用者向け（タグ `v1.0-lab-rc2`）

Ninlil V1 LAB は **隔離された LAB 環境** で動作する host simulation 完成版です。
国内実運用可能・production 法規認定は **主張しません**（V2）。

## 前提

- Linux または macOS
- CMake ≥ 3.16、C11 コンパイラ
- OpenSSL 3.x（Host R7 crypto; tests ビルド時必須）
- SQLite3（POSIX durable storage port）

## ビルド

```bash
git clone <repository>
cd ninlil-d3s3-implementation
cmake -S . -B tmp-v1 \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build tmp-v1 -j
ctest --test-dir tmp-v1 --output-on-failure
```

## 概念（最小）

| 用語 | V1 LAB での意味 |
| --- | --- |
| **submit** | Product intent を Runtime に投入（`ninlil_submit`） |
| **delivery** | 対向 Runtime の service callback へ payload 到達 |
| **evidence** | RECEIVED / DURABLY_RECORDED / APPLIED 等の段階的証拠 |
| **outcome** | submit 元が観測する最終結果（timeout / retry 含む） |
| **LAB_ONLY** | 送信可能 frame type・permit・profile が閉じた enforcement プロファイル |

縦切り経路（統合 gate）:

`submit → admission → durable queue → USB/Cell software path → AEAD wire → radio sim → RX auth → delivery → evidence → ACK/Receipt → outcome`

詳細: `docs/work/2026-07-23-v1-integration-gate-evidence.md`

## Host simulation examples

build tree で 4 本の最小例（いずれも `submit → delivery`）:

| Example | 相当ノード | 経路 |
| --- | --- | --- |
| `ninlil_v1_lab_controller_submit_example` | Site Controller | 統合 topology 下行 DesiredState |
| `ninlil_v1_lab_cell_custody_example` | Cell Agent | 統合 topology（USB custody + radio TX） |
| `ninlil_v1_lab_display_latest_state_example` | Display | 2-process loopback 上行 LatestState |
| `ninlil_v1_lab_leak_measurement_example` | Leak | 2-process loopback 上行 MeasurementBatch（submit 受理 + bearer egress; controller 完全 delivery は item 6 family CTest で検証） |

```bash
cd tmp-v1
./ninlil_v1_lab_controller_submit_example
./ninlil_v1_lab_cell_custody_example
./ninlil_v1_lab_display_latest_state_example
./ninlil_v1_lab_leak_measurement_example
```

または:

```bash
ctest -R 'v1_lab_.*_example' --output-on-failure
```

## Installable package（外部 consumer）

POSIX SQLite port を CMake package として install し、外部 consumer が
`find_package(Ninlil)` で link できることを smoke で検証します。

```bash
tools/v1_lab_consumer_smoke.sh
```

配布物一覧: `docs/v1-lab-distribution-manifest.md`

## V1 でないもの（明示）

- SBOM / release signing（V2）
- 物理 USB / RF / flash / power-cut HIL
- Display / Leak **実機** node E2E
- production 法規認定・「国内実運用可能」表示

残件: `docs/work/2026-07-23-v1-rc-residuals.md`  
V2 roadmap: `docs/work/2026-07-23-ninlil-v1-lab-plan.md` §2

## 次の読み物

- 開発者向け: `docs/v1-lab-developer.md`
- 計画正本: `docs/work/2026-07-23-ninlil-v1-lab-plan.md`
- Public API: `docs/04-runtime-api-and-storage.md`
