# Ninlil Runtime

Ninlil Runtime は、LoRa・Wi-Fi・USB など不安定で帯域の狭い現場ネットワーク上で、「送信した」ではなく **届いた・保存された・適用された** を分けて追跡する、組み込み向け通信 Runtime / SDK です。

KGuard は最初の reference application ですが、Ninlil Core は KGuard の業務語彙を知りません。Bearer・期限・宛先・必要な証拠・電力・容量・経路・法規上の制約に基づいて通信を管理します。

## V1 LAB RC2 の状態

**タグ [`v1.0-lab-rc2`](https://github.com/Aero123421/Ninlil-Runtime/releases/tag/v1.0-lab-rc2)** の **V1 LAB RC2** は、隔離 LAB 向け host simulation の **機能完成** リリースです。縦切り 10 項目（コード・テスト・文書・統合 E2E）が揃い、stub / TODO / 未接続は 0 です。統合 E2E gate（単一 topology 全経路 + 9 故障注入）で false success 0・bounded termination・範囲外 fail-closed を実証しています。

**LAB_ONLY** — 国内実運用可能・production 法規認定は **主張しません**。物理 USB / RF / flash / power-cut HIL は **未完了**（[RC 残件](docs/work/2026-07-23-v1-rc-residuals.md)）。V2 以降の巨大 oracle 網羅・relay・multi-parent・完全 wire fragmentation・形式証明・SBOM / signing は本リリースのスコープ外です。

## 検証区分（host verified / HIL pending / V2）

| 区分 | 内容 |
| --- | --- |
| **host verified** | POSIX SQLite durable storage、public Runtime body、capability、Join / Attachment、secure wire（NRW1）、USB / radio **software path**（host simulation）、2-process E2E、examples 4 本 build+run、full CTest（通常 + ASan/UBSan） |
| **HIL pending** | ESP flash / USB 実機、SX1262 physical RF TX/RX、power-cut / FULL durable attestation（ESP）、USB CDC HIL、Display / Leak **実機** node E2E（[RC 残件](docs/work/2026-07-23-v1-rc-residuals.md)） |
| **V2** | D3-S4..S12 網羅、relay、multi-parent、完全 wire fragmentation、production 法規認定、形式証明、SBOM / release signing |

## 構成（V1 LAB host simulation）

```
 Application (submit / service callbacks)
        |
        v
 +------------------+
 |  Public API      |  ninlil_submit, service_register, runtime_step, ...
 +------------------+
        |
        v
 +------------------+
 |  Runtime         |  admission / delivery / evidence / outcome
 |  (durable spine) |
 +------------------+
        |
   +----+----+
   |         |
   v         v
 Durable    Secure wire + bearer
 store      (POSIX SQLite)   (C4/C5/C6 LAB + loopback sim)
   |              |
   |              v
   |         USB / radio software path
   |              |
   +------+-------+
          v
       Peer Runtime
```

## 5 分 quickstart

前提: Linux または macOS、CMake ≥ 3.16、C11 コンパイラ、**OpenSSL 3.x**（tests 時）、**SQLite3**（POSIX storage port）。

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
cmake -S . -B tmp-v1 \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build tmp-v1 -j
ctest --test-dir tmp-v1 --output-on-failure
```

詳細: [docs/v1-lab-quickstart.md](docs/v1-lab-quickstart.md)

## Examples（host simulation）

`examples/v1_lab/` の 4 本。いずれも `submit → delivery`（または Measurement の bearer egress）を host 上で再現します。

| Example | 説明 | 実行 |
| --- | --- | --- |
| **Controller** | Site Controller から統合 topology へ DesiredState を submit | `cd tmp-v1 && ./ninlil_v1_lab_controller_submit_example` |
| **Cell** | Cell Agent — USB custody + radio TX 経路 | `cd tmp-v1 && ./ninlil_v1_lab_cell_custody_example` |
| **Display** | Display ノード相当の 2-process loopback 上行 LatestState | `cd tmp-v1 && ./ninlil_v1_lab_display_latest_state_example` |
| **Leak** | Leak ノード相当の 2-process loopback 上行 MeasurementBatch | `cd tmp-v1 && ./ninlil_v1_lab_leak_measurement_example` |

一括実行: `ctest -R 'v1_lab_.*_example' --test-dir tmp-v1 --output-on-failure`

## Capability / Service / ApplicationData

[Application Contracts（docs/02）](docs/02-application-contracts.md) に準拠します。

- **Service（`ServiceDescriptor`）** — Runtime 起動時に登録する静的な通信契約（contract family、方向、payload 上限、required evidence、route / bearer 方針など）。
- **Capability** — Join / Attachment 後に確定する effective capability（requested ∩ device supported ∩ policy）。Admission は fresh capability snapshot で検査します（[Identity and Join（docs/03）](docs/03-identity-and-join.md) §Capability negotiation）。
- **ApplicationData** — admission 後に Runtime が所有する 1 件の論理 data / intent の **概念名**です。独立した public C type ではなく、**Transaction + payload + descriptor snapshot** として durable store に保存します（docs/02 §SubmissionとApplicationData）。

## Build と test

| 種別 | コマンド |
| --- | --- |
| 通常 Debug | `cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j && ctest --test-dir build --output-on-failure` |
| ASan / UBSan | `CC=clang CXX=clang++ cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug -DNINLIL_ENABLE_SANITIZERS=ON && cmake --build build-sanitize -j && ctest --test-dir build-sanitize --output-on-failure` |

**前提:** Python 3（vector oracle 生成）、OpenSSL 3.x（Host R7 crypto tests）、SQLite3 development package（POSIX storage port; 未検出時は port のみ skip）。

統合 E2E gate: `ctest -R v1_integration_gate --test-dir tmp-v1 --output-on-failure`

## 対応 platform

| Platform | 状態 |
| --- | --- |
| **POSIX host（Linux / macOS）** | **verified** — LAB quickstart・examples・統合 E2E・consumer install smoke |
| **ESP-IDF v5.5.3（ESP32-S3 target build）** | compile / link smoke（`.github/workflows/esp-idf.yml`）。**HIL 未** — flash / USB 実機 / RF / power-cut は RC 残件 |

## 制限・security・法規

- **LAB_ONLY** — 国内実運用・production 法規認定・field SLO は主張しません。
- 脆弱性報告: [SECURITY.md](SECURITY.md)（非公開 Security Advisory 経由）。
- ライセンス: [Apache License 2.0](LICENSE)。

## ドキュメント

| 文書 | 内容 |
| --- | --- |
| [Documentation index](docs/README.md) | 仕様の読み順・正本ルール |
| [V1 LAB quickstart](docs/v1-lab-quickstart.md) | 利用者向けビルド・examples |
| [V1 LAB developer](docs/v1-lab-developer.md) | 開発者向け layout・テスト・provider |
| [Distribution manifest](docs/v1-lab-distribution-manifest.md) | 配布物一覧 |
| [RC 残件](docs/work/2026-07-23-v1-rc-residuals.md) | 物理実機系のみの残作業 |
| [CHANGELOG](CHANGELOG.md) | 利用者向け変更履歴 |
| [CONTRIBUTING](CONTRIBUTING.md) | 貢献手順 |
| [Pre-V1 実装履歴](docs/release-history.md) | M0–R7 candidate スライス履歴（README から退避） |

仕様の入口: [Project Charter](docs/00-project-charter.md) → [Architecture](docs/01-architecture.md) → [Application Contracts](docs/02-application-contracts.md) → [Runtime API](docs/04-runtime-api-and-storage.md)

## License

Ninlil Runtime は [Apache License 2.0](LICENSE) で提供します。
