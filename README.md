# Ninlil Runtime

Ninlil Runtime は、LoRa・Wi-Fi・USB など不安定で帯域の狭い現場ネットワーク上で、「送信した」ではなく **届いた・保存された・適用された** を分けて追跡する、組み込み向け通信 Runtime / SDK です。

Ninlil Core は、特定のアプリケーション固有の業務語彙に依存しません。Bearer・期限・宛先・必要な証拠・電力・容量・経路・法規上の制約に基づいて通信を管理します。

## 現在の状態

**V1 LAB RC2 は host simulation の検証用候補であり、完成したRuntime SDKではありません。**
タグ [`v1.0-lab-rc2`](https://github.com/Aero123421/Ninlil-Runtime/releases/tag/v1.0-lab-rc2)
には統合E2Eと多数の故障試験があります。現在の `main` の install package は
公開header、`Ninlil::runtime`、および任意の POSIX SQLite port を export します。
また、公開API、完全なdurable admission/restart、payload実配送、実Wi-Fi/RF、
relay、multi-parent、完全fragmentationには未完了項目があります。

現在は、[V2 Runtime Fabric Completion Contract](docs/34-v2-runtime-fabric-completion.md)
に基づき、機能ごとに仕様、実装、Host/ESP試験、HIL、互換性、release evidenceを
閉じる作業を進めています。概算パーセントやテスト件数だけでは完成扱いにしません。

**LAB_ONLY** — 国内実運用可能・production 法規認定は **主張しません**。物理
USB / RF / flash / power-cut HILも未完了です。

### 完成までの進捗台帳

`RELEASE_SUPPORTED`だけを100%完成と呼びます。`SPEC_ACCEPTED`は実装開始可能な
仕様が固まった状態、`HOST_CANDIDATE`と`TARGET_CANDIDATE`はそれぞれHostとESP targetの
実装候補であり、実機確認の代わりにはなりません。

| 機能 | 現在の状態 | 次の必須gate |
| --- | --- | --- |
| Portable Core / Host Runtime | **HOST_CANDIDATE修正中** | durable lifecycleの独立レビューP0/P1=0、通常・sanitizer・package CI |
| Canonical Domain Store | **PROPOSED** | ADR-0022の独立受入後、bootstrap / recovery / migrationの実装とcrash matrix |
| Identity / Attachment / session install | **PROPOSED** | M4/M5のexact pre-attachment carrier、FULL durable Attachment、Hop/E2E key installとrestart/HIL |
| Fabric Bearer / NFL1 / path registry | **PROPOSED** | ADR-0017のexact API・storage・vectorを`SPEC_ACCEPTED`へ |
| POSIX TCP/TLS Wi-Fi reference | **UNALLOCATED（実装0）** | ADR-0017後にADR-0018を受入し、codec→Fabric→TCP→TLSの順でHost実装 |
| ESP32-S3 Wi-Fi STA/TCP/TLS | **UNALLOCATED（実装0）** | Host候補後、pinned ESP-IDF target build・target test・実AP HIL |
| NRW1 LINK / FRAG / reassembly | **SPEC_ACCEPTED相当のR6設計、実装未完** | R7 state/wire materialization、loss/reorder/restart試験、RF HIL |
| Relay | **PROPOSED** | FabricとLINK/FRAG後にADR-0019受入、2〜3 hop実装・3台以上RF HIL |
| Multi-parent / multi-Controller | **PROPOSED** | Relay後にADR-0020受入、single-owner fence・handoff・split-brain試験 |
| Multi-frame durable transfer | **PROPOSED** | ADR-0021受入、chunk custody・再構成・power-cut matrix |
| OSS package / docs / release CI | **HOST_CANDIDATE** | 全featureのsupport matrix、互換性、SBOM・attestation付きrelease、独立review |

物理USB、SX1262 RF、flash power-cut、実AP、24時間soakは、対応機材を接続して得た
再現可能なartifactが揃うまで`HIL_VERIFIED`へ進めません。現在の詳細な依存順と
完成条件は[34章](docs/34-v2-runtime-fabric-completion.md)を正本とします。

## 検証区分（host verified / HIL pending / V2）

| 区分 | 内容 |
| --- | --- |
| **host verified** | POSIX SQLite storage port、Foundation model、NRW1 SINGLE codec、USB / radio **software path**（host simulation）、2-process LAB E2E、examples 4 本 build+run、full CTest（通常 + ASan/UBSan） |
| **HIL pending** | ESP flash / USB 実機、SX1262 physical RF TX/RX、power-cut / FULL durable attestation（ESP）、USB CDC HIL、Display / Leak **実機** node E2E（[RC 残件](docs/work/2026-07-23-v1-rc-residuals.md)） |
| **completion work** | 全public API、canonical durable admission/restart、payload配送、Wi-Fi、relay、multi-parent、完全wire fragmentation |

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

前提: Linux または macOS、CMake ≥ 3.20、C11 コンパイラ、**OpenSSL 3.x**（Host Runtime / host tests）。**SQLite3** は任意の POSIX storage port 用です。
Repository の build / CTest と install 済み CMake package の独立 consumer は、
どちらも CMake ≥ 3.20 を要求します。

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
cmake -S . -B tmp-v1 \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build tmp-v1 -j
ctest --test-dir tmp-v1 --output-on-failure
```

現行SDKの詳細: [Host Runtime SDK](docs/host-runtime-sdk.md)

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
| **POSIX host（Linux x86_64 / macOS arm64）** | **HOST_CANDIDATE** — LAB quickstart・examples・統合 E2E・consumer install smokeはHost検証済み。Release supportの主張ではない |
| **ESP-IDF v5.5.3（ESP32-S3 target build）** | compile / link smoke（`.github/workflows/esp-idf.yml`）。**HIL 未** — flash / USB 実機 / RF / power-cut は RC 残件 |

## 制限・security・法規

- **LAB_ONLY** — 国内実運用・production 法規認定・field SLO は主張しません。
- 脆弱性報告: [SECURITY.md](SECURITY.md)（非公開 Security Advisory 経由）。
- ライセンス: [Apache License 2.0](LICENSE)。

## ドキュメント

| 文書 | 内容 |
| --- | --- |
| [Documentation index](docs/README.md) | 仕様の読み順・正本ルール |
| [Host Runtime SDK](docs/host-runtime-sdk.md) | 現行CMake packageのbuild・install・利用 |
| [SDK distribution manifest](docs/sdk-distribution-manifest.md) | 現行install tree・export境界・release artifacts |
| [Compatibility matrix](compatibility-matrix.json) | version・platform・feature状態・HIL境界のmachine-readable正本 |
| [Dependency inventory](dependency-inventory.json) | Host / ESP-IDF dependency、version、license、lock hash、container digestのmachine-readable正本 |
| [V1 LAB quickstart](docs/v1-lab-quickstart.md) | `v1.0-lab-rc2`履歴スナップショット |
| [V1 LAB developer](docs/v1-lab-developer.md) | `v1.0-lab-rc2`開発者向け履歴 |
| [V1 LAB distribution](docs/v1-lab-distribution-manifest.md) | `v1.0-lab-rc2`配布履歴 |
| [RC 残件](docs/work/2026-07-23-v1-rc-residuals.md) | 物理実機系のみの残作業 |
| [CHANGELOG](CHANGELOG.md) | 利用者向け変更履歴 |
| [CONTRIBUTING](CONTRIBUTING.md) | 貢献手順 |
| [Pre-V1 実装履歴](docs/release-history.md) | M0–R7 candidate スライス履歴（README から退避） |

仕様の入口: [Project Charter](docs/00-project-charter.md) → [Architecture](docs/01-architecture.md) → [Application Contracts](docs/02-application-contracts.md) → [Runtime API](docs/04-runtime-api-and-storage.md)

## License

Ninlil Runtime は [Apache License 2.0](LICENSE) で提供します。
