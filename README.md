# Ninlil Runtime

[![CI](https://github.com/Aero123421/Ninlil-Runtime/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Aero123421/Ninlil-Runtime/actions/workflows/ci.yml?query=branch%3Amain)

Ninlil Runtime は、LoRa・Wi-Fi・USB など不安定で帯域の狭い現場ネットワーク上で、「送信した」ではなく **届いた・保存された・適用された** を分けて追跡する、組み込み向け通信 Runtime / SDK です。

Ninlil Core は、特定のアプリケーション固有の業務語彙に依存しません。Bearer・期限・宛先・必要な証拠・電力・容量・経路・法規上の制約に基づいて通信を管理します。

[English overview](README.en.md)

## 現在の状態

`main` は Portable Core / Host Runtime と OSS 配布境界を持つ**プレリリース SDK**です。

### 今日使える範囲

- 公開 C header と `Ninlil::runtime`、`Ninlil::fabric_v1` を install できます。
- Linux/macOS では `Ninlil::posix_tls_v1`、`Ninlil::posix_usb_serial_v1`、任意の
  POSIX SQLite storage port を利用できます。
- Host software と installed consumer の検証があります。入口は下の focused smoke と
  [Host Runtime SDK](docs/host-runtime-sdk.md) です。

### まだ証明されていない範囲

- production 運用、920 MHz 法規適合、field SLO、remote release 成功。
- 物理 USB/RF、実 AP、flash power-cut、24 時間 soak を含む実機 HIL。
- private の relay、multi-parent、multi-frame transfer を個別の public ABI として提供すること。

> **LAB_ONLY / pre-release:** target compile や Host simulation は、実機 HIL の代わりではありません。

完成判定の正本は [Compatibility matrix](compatibility-matrix.json) と
[V2 Runtime Fabric Completion Contract](docs/34-v2-runtime-fabric-completion.md) です。
長い実装根拠、次 gate、V1 の残件は [Current status](docs/status.md) に分離しました。

### Compact state

`RELEASE_SUPPORTED` だけを完成と呼びます。注記は候補の種類であり、先頭の状態を昇格しません。

| 機能 | 現在の状態 |
| --- | --- |
| Portable Core / Host Runtime | **SPEC_ACCEPTED / local Host候補** |
| Canonical Domain Store | **SPEC_ACCEPTED / scanner・target build候補** |
| Identity / Attachment / session install | **PROPOSED / repair中** |
| Fabric Bearer / NFL1 / path registry | **SPEC_ACCEPTED / experimental public package** |
| POSIX TCP/TLS Wi-Fi reference | **PROPOSED** |
| POSIX TCP/TLS reference | **SPEC_ACCEPTED / experimental public Host package** |
| POSIX USB serial reference | **SPEC_ACCEPTED / experimental public Host package** |
| ESP32-S3 Wi-Fi STA/TCP/TLS | **PROPOSED / TLS target build合格** |
| NRW1 LINK / FRAG / reassembly | **SPEC_ACCEPTED / target build合格** |
| Relay | **SPEC_ACCEPTED / software候補レビュー合格** |
| Multi-parent / multi-Controller | **SPEC_ACCEPTED / software候補レビュー合格** |
| Multi-frame durable transfer | **SPEC_ACCEPTED / Host software候補** |
| V1 composition | **SPEC_ACCEPTED / Host・ESP package候補** |
| V1 functional LAB vertical slice | **PROPOSED / Host・target候補** |
| OSS package / docs / release CI | **HOST_CANDIDATE** |

## アーキテクチャ

```
 Application services / arbitrary ApplicationData
                    |
                    v
        +--------------------------+
        | Portable Runtime Core    |
        | admission / deadline     |
        | retry / dedupe / outcome |
        +------------+-------------+
                     |
           +---------+---------+
           v                   v
    Durable Storage       Fabric / Bearers
    POSIX SQLite          Wi-Fi / USB / LoRa
           |                   |
           +---------+---------+
                     v
               Peer Runtime
```

Coreはsocket、ESP-IDF、SX1262、アプリ固有語彙を知りません。platform adapterが
storage・clock・entropy・Bearerを提供し、private機能はAccepted public ABIの外側で
段階的に昇格します。

## Quickstart（focused smoke）

前提: Linux または macOS、CMake ≥ 3.20、C11 / C++17 compiler、Python 3、
**Node.js ≥18**、**OpenSSL 3.x**（Host Runtime / host tests）。このfocused smokeは
POSIX LAB platformを使うためSQLite3 development packageも必要です（library package
自体ではPOSIX SQLite portは任意）。Repository の build / CTest とinstall済みCMake
packageの独立consumerは、どちらもCMake ≥ 3.20を要求します。

```bash
git clone https://github.com/Aero123421/Ninlil-Runtime.git
cd Ninlil-Runtime
cmake -S . -B tmp-v1 -DCMAKE_BUILD_TYPE=Debug
cmake --build tmp-v1 --target ninlil_v1_integration_gate_e2e_test --parallel
ctest --test-dir tmp-v1 -R '^v1_integration_gate_e2e$' --output-on-failure
```

これは入口用の focused smoke です。全 CTest、private candidate、sanitizer は別の
検証であり、5分で終わることを約束しません。

### Sanitizer と全 suite

CI の sanitizer profile は Clang を使います（CMake option 自体は GNU / Clang /
AppleClang を受け付けます）。Clang本体に加えて対応するASan/UBSan runtimeが必要です
（Ubuntuの例: `libclang-rt-dev`、version固定環境では`libclang-rt-18-dev`）。全 suite は
通常 build と sanitizer build を分けて実行してください。

```bash
cmake --build tmp-v1 --parallel
ctest --test-dir tmp-v1 --output-on-failure
CC=clang CXX=clang++ cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

### 最小 C SDK 例

次はpublic Runtime APIの主経路です。`config`、`descriptor`、`callbacks`、`submission`
はABI headerを含めて初期化済み、`submission`はAPPLIED evidenceを要求するvalidな
1-target submission、
`platform.storage`はRuntime再起動後も同じ永続provider、`platform.bearer`はpeerからの
Receiptを`step`中に返す前提です。完全なprovider実装と
初期値は [Host Runtime SDK](docs/host-runtime-sdk.md) のinstalled consumerを参照してください。

```c
#include <ninlil/runtime.h>
#include <string.h>

#define INIT(v) do { memset(&(v), 0, sizeof(v)); \
    (v).abi_version = NINLIL_ABI_VERSION; \
    (v).struct_size = (uint16_t)sizeof(v); } while (0)

int run_transaction(const ninlil_runtime_config_t *config,
                    const ninlil_platform_ops_t *platform,
                    const ninlil_service_descriptor_t *descriptor,
                    const ninlil_service_callbacks_t *callbacks,
                    const ninlil_submission_t *submission) {
    ninlil_runtime_t *runtime = NULL;
    ninlil_service_t *service = NULL;
    ninlil_submission_result_t admitted;
    ninlil_step_budget_t budget;
    ninlil_step_result_t stepped;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target;
    uint32_t turn;

    INIT(admitted); INIT(budget); INIT(stepped); INIT(snapshot); INIT(target);
    budget.max_ingress_messages = budget.max_callbacks = 4;
    budget.max_state_transitions = budget.max_bearer_sends = 4;
    snapshot.targets = &target; snapshot.target_capacity = 1;
    if (ninlil_runtime_create(config, platform, &runtime) != NINLIL_OK ||
        ninlil_service_register(runtime, descriptor, callbacks, &service) != NINLIL_OK ||
        ninlil_submit(service, submission, &admitted) != NINLIL_OK ||
        (admitted.kind != NINLIL_SUBMISSION_ADMITTED_READY &&
         admitted.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED)) goto fail;
    for (turn = 0; turn < 64; ++turn) {
        INIT(stepped);
        if (ninlil_runtime_step(runtime, &budget, &stepped) != NINLIL_OK ||
            ninlil_transaction_query(runtime, &admitted.transaction_id, &snapshot)
                != NINLIL_OK) goto fail;
        if (snapshot.outcome == NINLIL_OUTCOME_SATISFIED) break; /* Receipt applied */
    }
    if (turn == 64) goto fail;
    if (ninlil_runtime_destroy(runtime) != NINLIL_OK) return 1;
    runtime = NULL; service = NULL; INIT(snapshot); INIT(target);
    snapshot.targets = &target; snapshot.target_capacity = 1;
    if (ninlil_runtime_create(config, platform, &runtime) != NINLIL_OK ||
        ninlil_service_register(runtime, descriptor, callbacks, &service) != NINLIL_OK ||
        ninlil_transaction_query(runtime, &admitted.transaction_id, &snapshot)
            != NINLIL_OK || snapshot.outcome != NINLIL_OUTCOME_SATISFIED) goto fail;
    return ninlil_runtime_destroy(runtime) == NINLIL_OK ? 0 : 1;
fail:
    if (runtime != NULL) (void)ninlil_runtime_destroy(runtime);
    return 1;
}
```

これはlifecycleの要点だけです。productionでは固定64回待ちではなく、
`ninlil_step_result_t`のwake情報とplatform event loopで再駆動してください。

### 近い protocol との違い

| Protocol | Ninlil の範囲 |
| --- | --- |
| MQTT-SN | publish/subscribe protocol を置き換えるものではなく、Ninlil は application outcome と durable evidence を追跡する Runtime。 |
| LoRaWAN | radio network / join の代替ではなく、Ninlil はその上を含む bearer の選択と結果追跡を扱う。 |
| CoAP | request/response protocol の代替ではなく、Ninlil は不安定な bearer をまたぐ application transaction を扱う。 |
| Zenoh | data-centric pub/sub/query の代替ではなく、Ninlil は現場 bearer 上の application transaction とその証拠を扱う。 |

### V1 USB Controller接続プローブ（private LAB）

Linux/macOSで、USB親機とのclock照合、1〜2個のexact binding適用、SQLite-backed
Composition生成、最大4 pathのFabric登録を確認できます。任意で1件のDesiredStateを
指定peer/Serviceへ送り、VERIFIED Receiptまで待てます。既定ではbuildされず、Domain
schema 1候補との同時利用も意図的に拒否します。

```bash
cmake -S . -B tmp-controller \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_V1_LAB_CONTROLLER=ON \
  -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=OFF
cmake --build tmp-controller \
  --target ninlil_v1_lab_controller ninlil_v1_lab_controller_probe_test -j
ctest --test-dir tmp-controller -R '^v1_lab_controller_probe$' \
  --output-on-failure

./tmp-controller/ninlil_v1_lab_controller \
  --usb /dev/cu.usbmodem-DEVICE \
  --database ./controller.sqlite3 \
  --binding ./peer-a.nlb1 \
  --binding ./peer-b.nlb1 \
  --send-binding 1 \
  --send-service 1 \
  --payload-hex 01020304
```

接続確認だけなら末尾の`--send-*`と`--payload-hex`を省略します。

bindingは秘密を含むprivate LAB配布物です。プローブは内容を表示せず、binding pathの
最終componentがsymlinkのもの、hard-link、実行ユーザー以外が所有するファイル、
group/other権限付きファイルを拒否します。現段階では接続確認後に終了し、Application
送信は上記の一回診断だけです。常駐運転、binding発行・在庫管理は行いません。

現行SDKの詳細: [Host Runtime SDK](docs/host-runtime-sdk.md)

### installしてCMakeから使う

focused smokeのbuild dirは必要な1 targetだけを生成するため、installはtests-OFFの
専用buildから行います。

```bash
cmake -S . -B tmp-install-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNINLIL_BUILD_TESTS=OFF \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_FABRIC_V1=ON
cmake --build tmp-install-build --parallel
cmake --install tmp-install-build --prefix "$PWD/tmp-install"
```

consumer側:

```cmake
find_package(Ninlil CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Ninlil::runtime)
```

用途に応じて`Ninlil::fabric_v1`、`Ninlil::posix_tls_v1`、
`Ninlil::posix_usb_serial_v1`も同じinstalled packageからlinkできます。

POSIX SQLite adapterのexport名と、testsを含まないclean installの確認方法は
[Host Runtime SDK](docs/host-runtime-sdk.md)を参照してください。

### private候補を開発・検証する

以下は既定で`OFF`です。公開ABIやproduction supportを意味しません。

| CMake option | 候補機能 |
| --- | --- |
| `NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING` | Canonical Domain Store runtime binding |
| `NINLIL_ENABLE_PRIVATE_FABRIC_V1` | Fabric registry / NFL1 / path selection |
| `NINLIL_ENABLE_PRIVATE_WIFI_V1` | POSIX/ESP Wi‑Fi packet-link |
| `NINLIL_ENABLE_R7_FRAG_PRIVATE` | secure radio fragmentation/reassembly |
| `NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1` | relay / multi-parent |
| `NINLIL_ENABLE_MFDT_V1_PRIVATE` | multi-frame durable transfer |

全private候補を同時にHost検証する例:

```bash
cmake -S . -B tmp-all-private -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON \
  -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON \
  -DNINLIL_ENABLE_PRIVATE_WIFI_V1=ON \
  -DNINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=ON \
  -DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON \
  -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON
cmake --build tmp-all-private -j
ctest --test-dir tmp-all-private --output-on-failure
```

system OpenSSLを使うWi‑Fi Host buildはLAB用です。authority証拠には
`tools/wifi_v1_build_pinned_openssl.sh`とCIで固定したOpenSSL profileを使います。

## Generic example

最初に [`examples/multi_service_node/`](examples/multi_service_node/) を参照してください。
Ninlil の公開型だけで、1つの role-neutral node に4つの Service（command、event、
telemetry、query）を同時登録する profile です。製品固有語彙を含まず、Host の実 Runtime / Fabric
縦断で検証されます。現行の検証 harness は private Fabric gate 配下です。

```bash
cmake -S . -B tmp-generic -DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON
cmake --build tmp-generic --target ninlil_runtime_fabric_actual_e2e_test --parallel
ctest --test-dir tmp-generic -R '^multi_service_node_host_actual_e2e$' --output-on-failure
```

## V1 LAB examples（host simulation）

`examples/v1_lab/` の 4 本。いずれも host 上で `submit → delivery` を再現します。
実行前に、focused quickstart と同じ build directory へ4本をbuildします。

```bash
cmake --build tmp-v1 --parallel --target \
  ninlil_v1_lab_controller_submit_example \
  ninlil_v1_lab_cell_custody_example \
  ninlil_v1_lab_display_latest_state_example \
  ninlil_v1_lab_leak_measurement_example
```

**M1a 公開 family は DesiredState + EventFact のみ**（[ADR-0024](docs/adr/0024-m1a-public-family-matrix-freeze.md)）。named reserved `LATEST_STATE_RESERVED` / `MEASUREMENT_RESERVED` は `service_register = NINLIL_E_UNSUPPORTED` のままで、first-class public family ではありません。Display / Leak は製品ラベルの **display snapshot event (EventFact)** / **leak measurement event (EventFact)** です（service_id 文字列は `latest-state` / `leak-measurement` だが family enum は EventFact）。

| Example | 説明 | 実行（historical target name; label-only） |
| --- | --- | --- |
| **Controller** | Site Controller から統合 topology へ DesiredState を submit | `cd tmp-v1 && ./ninlil_v1_lab_controller_submit_example` |
| **Cell** | Cell Agent — USB custody + radio TX 経路 | `cd tmp-v1 && ./ninlil_v1_lab_cell_custody_example` |
| **Display** | Display ノード相当の 2-process loopback 上行 — **display snapshot event (EventFact)** | `cd tmp-v1 && ./ninlil_v1_lab_display_latest_state_example` |
| **Leak** | Leak ノード相当の 2-process loopback 上行 — **leak measurement event (EventFact)** | `cd tmp-v1 && ./ninlil_v1_lab_leak_measurement_example` |

Executable / CTest 名 `*_display_latest_state_*` / `*_leak_measurement_*` は **互換用の historical label のみ**（deprecation 候補; 改名しない）。reserved public family の有効化を意味しません（ADR-0024）。

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

**前提:** Python 3（vector oracle 生成）、Node.js ≥18（independent specification gates）、OpenSSL 3.x（Host R7 crypto tests）、SQLite3 development package（POSIX storage port; 未検出時は port のみ skip）。

統合 E2E gate: `ctest -R v1_integration_gate --test-dir tmp-v1 --output-on-failure`

## 対応 platform

| Platform | 状態 |
| --- | --- |
| **POSIX host（Linux x86_64 / macOS arm64）** | **HOST_CANDIDATE（software-ready）** — LAB quickstart・examples・統合 E2E・consumer install smoke・release archive clean-room は Host ソフトウェア検証対象。**`RELEASE_SUPPORTED` ではない**。物理 HIL は未 |
| **ESP-IDF v5.5.3（ESP32-S3 target build）** | compile / link smoke（`.github/workflows/esp-idf.yml`）。**HIL pending** — flash / USB 実機 / RF / power-cut は RC 残件（software smoke ≠ field HIL） |

## 制限・security・法規

- **LAB_ONLY** — 国内実運用・production 法規認定・field SLO は主張しません。
- 脆弱性報告: [SECURITY.md](SECURITY.md)（非公開 Security Advisory 経由）。
- ライセンス: [Apache License 2.0](LICENSE)。

## ドキュメント

| 文書 | 内容 |
| --- | --- |
| [Documentation index](docs/README.md) | 仕様の読み順・正本ルール |
| [Current status](docs/status.md) | 詳細な実装根拠・次 gate・実機残件（informative） |
| [Host Runtime SDK](docs/host-runtime-sdk.md) | 現行CMake packageのbuild・install・利用 |
| [Build options](docs/build-options.md) | user-facing CMake option / cache variable一覧 |
| [SDK distribution manifest](docs/sdk-distribution-manifest.md) | 現行install tree・export境界・release artifacts |
| [Compatibility matrix](compatibility-matrix.json) | version・platform・feature状態・HIL境界のmachine-readable正本 |
| [Dependency inventory](dependency-inventory.json) | Host / ESP-IDF dependency、version、license、lock hash、container digestのmachine-readable正本 |
| [Release Guide](docs/releasing.md) | immutable source identity、source archive、SBOM、attestationの公開手順 |
| [Requirements traceability](requirements-traceability.yaml) | Foundation PR1の試験登録対応表。Registration Coverage V2がbaseline / all-private両profileのNormative見出し・要件・vector・invariantと、有効なCTest名・source anchorの対応を検査する。CIでは別実行のJUnitから引用CTestのPASSも要求するが、assertion強度やcoverageの証明ではない |
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
