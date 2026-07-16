# 18. M3-prep: ESP-IDF component packaging

状態: Informative packaging / CI prep（**M3 incomplete**）  
対象: portable Core / private Runtime を ESP32-S3 target で **compile** できる component 境界

## 1. この文書の位置付け

本章は [09-roadmap.md](09-roadmap.md) の **M3** のうち、先に固定できる **component packaging と pinned target build** だけを記述します。

次を **主張しません**:

- ESP-IDF port の完了
- M3 milestone の完了
- 実機 hardware 検証の完了
- V1 release の完了
- NVS / FreeRTOS owner task / USB / Wi-Fi / SX1262 / radio MAC / Join / KGuard adapter 実装済み

M3 全体の exit gate（POSIX と同一 portable conformance subset、power-cut HIL、Cell Agent skeleton 等）は未達です。本章は **M3-prep** に限定します。

関連境界:

| 文書 | 本章との関係 |
| --- | --- |
| [08-foundation-release.md](08-foundation-release.md) | portable core は OS thread / filesystem / SQLite に直接依存しない |
| [09-roadmap.md](09-roadmap.md) M3 | packaging は M3 の先頭 slice。本章は packaging のみ |
| [12-foundation-abi.md](12-foundation-abi.md) | public ABI は変更しない |
| [14-foundation-ports-and-simulator.md](14-foundation-ports-and-simulator.md) | ESP-IDF storage/clock/entropy/execution port は **M3 本体**。本章は packaging のみ（basic/storage は 20/21 章） |
| [01-architecture.md](01-architecture.md) | `ports/esp-idf/` layout の初期配置 |

## 2. ESP-IDF version pin（再現可能）

### 2.1 Pin 値

| 項目 | 値 |
| --- | --- |
| ESP-IDF release tag | **`v5.5.3`** |
| 正本ファイル | [`ports/esp-idf/ESP_IDF_VERSION`](../ports/esp-idf/ESP_IDF_VERSION) |
| 公式 Docker image | `espressif/idf:v5.5.3` |
| Component Manager 依存 | `idf_component.yml` の `idf.version: "==5.5.3"` |
| CI | [`.github/workflows/esp-idf.yml`](../.github/workflows/esp-idf.yml) が上記 tag を読む |
| Build target | **`esp32s3`**（必須） |

`ports/esp-idf/ESP_IDF_VERSION`、本章、`idf_component.yml`、ESP-IDF workflow は **同一 concrete pin** でなければなりません。host CI（[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)）とは **分離** します。

### 2.2 選定理由（M3-prep 限定）

Web から「今日の最新 stable」を都度推測して pin しません。M3-prep では次の条件を満たす **既知の公式 stable release tag** を固定します。

1. Espressif が公開する **concrete tag 形式 `vX.Y.Z`** であること（`master` / `release-v5.x` のような浮動参照ではない）。
2. 公式の利用経路で再現できること。本 repository は **公式 Docker image `espressif/idf:<tag>`** を CI の setup 方式とする（外部 third-party Action に依存しない。`actions/checkout` のみ commit SHA pin）。
3. ESP32-S3 が supported target である世代の stable line であること。
4. 本 pin は **「現時点で保証する唯一の ESP-IDF 検証 version」** であり、より新しい tag への追従や multi-version matrix は後続作業とする。

**選定結果:** `v5.5.3` を M3-prep の pinned ESP-IDF とする。

これは「最新版である」ことの主張ではありません。M3-prep の **再現可能な既知安定版** としての固定です。version を上げる場合は `ESP_IDF_VERSION`、本章、`idf_component.yml`、workflow を同一 PR で更新し、ESP32-S3 smoke build を再証明します。

### 2.3 非目標（version 面）

- 複数 ESP-IDF major/minor の support matrix 宣言
- component registry への publish
- host compiler と ESP-IDF toolchain の ABI 互換保証
- production firmware support 宣言

## 3. Layout

```text
ports/esp-idf/
  ESP_IDF_VERSION                 # concrete pin vX.Y.Z
  components/
    ninlil/
      CMakeLists.txt              # idf_component_register
      idf_component.yml           # idf == pinned version, target esp32s3
  include/ninlil_esp_idf/         # port-owned factories（M3-basic; [20章](20-m3-basic-esp-idf-platform-adapters.md)）
  src/                            # ESP-IDF adapter pure + backend sources
  smoke_app/
    CMakeLists.txt                # EXTRA_COMPONENT_DIRS -> ../components
    main/main.c                   # public header + adapter compile/link smoke
    sdkconfig.defaults
cmake/
  ninlil_runtime_private_sources.cmake   # portable Core source authority
  ninlil_esp_idf_port_sources.cmake      # ESP-IDF port source authority（M3-basic）
```

portable 実装本体は従来どおり repository の `include/ninlil/` と `src/model/` / `src/runtime/` に置きます。ESP-IDF 固有 adapter を portable Core へ混ぜません。port-owned factory と backend は [20章](20-m3-basic-esp-idf-platform-adapters.md) です。

## 4. Source list 単一 authority

`ninlil_runtime_private` の production source 一覧は次の **1 ファイルだけ** が正本です。

- [`cmake/ninlil_runtime_private_sources.cmake`](../cmake/ninlil_runtime_private_sources.cmake)

| Consumer | 使い方 |
| --- | --- |
| 最上位 host [`CMakeLists.txt`](../CMakeLists.txt) | `include` して `add_library(ninlil_runtime_private ...)` |
| ESP-IDF component `ports/esp-idf/components/ninlil/CMakeLists.txt` | 同じ `include` で `idf_component_register(SRCS ...)` |

規則:

- `file(GLOB)` で source を集めない。
- `tests/`、`generated/`、`tools/`、TEST-only transport begin を component に入れない。
- ESP-IDF / FreeRTOS / NVS header を portable `src/**` へ include しない。
- host と component の list drift は [`tools/esp_idf_component_packaging_gate.py`](../tools/esp_idf_component_packaging_gate.py) が CTest で検査する。

## 5. Component 利用者向け最小導入

詳細手順と制約は [`ports/esp-idf/README.md`](../ports/esp-idf/README.md) を参照してください。要約:

1. ESP-IDF **`v5.5.3`** を用意する（公式 install または `espressif/idf:v5.5.3`）。
2. 自 project の `EXTRA_COMPONENT_DIRS` に `ports/esp-idf/components` を追加する。
3. app component の `REQUIRES` に `ninlil` を書く。
4. public header は `include/ninlil/*.h` のみを include する。
5. `idf.py set-target esp32s3 build` で **compile** できることを確認する。

この導入は **header + portable private library の target compile** までです。Runtime を現場で動かす storage/task/bearer port は含みません。

## 6. CI

| Workflow | 役割 |
| --- | --- |
| `.github/workflows/ci.yml` | host GCC normal + Clang ASan/UBSan + CTest（変更なしの意図） |
| `.github/workflows/esp-idf.yml` | 公式 image `espressif/idf:<ESP_IDF_VERSION>` で `esp32s3` smoke build |

ESP-IDF job は host `ctest` を実行しません。host job は ESP-IDF を install しません。

## 7. Local validation

推奨（公式 Docker、巨大な host への ESP-IDF install を避ける）:

```sh
pin="$(tr -d '[:space:]' < ports/esp-idf/ESP_IDF_VERSION)"
docker run --rm -v "$PWD:/project" -w /project "espressif/idf:${pin}" \
  bash -lc '. $IDF_PATH/export.sh && idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build'
```

ローカルに `idf.py` または image が無い場合、**勝手に数 GB の toolchain / image を導入せず**、CI の ESP-IDF workflow を evidence とします。

## 8. Acceptance（M3-prep のみ）

- [ ] host Debug build + CTest が従来どおり通る
- [ ] tests-OFF private archive の symbol gate が通る
- [ ] packaging gate が pin / authority / no-glob を通す
- [ ] pinned ESP-IDF で `esp32s3` smoke app が build できる（CI または local Docker）
- [ ] public ABI / wire / storage contract を変更していない
- [ ] 文書が M3 / port / hardware / V1 の完了を主張していない

## 9. 明示的に残る / 後続の M3 work

**M3-basic platform adapters**（clock / entropy / execution context）は [20章](20-m3-basic-esp-idf-platform-adapters.md) を正本とする別 slice です。本章の M3-prep packaging 完了は 20 章 adapter 完了を含みません。

本章 packaging の後に残る主な M3 work:

- partition storage候補は[21章](21-m3-esp-idf-durable-storage.md)で実装済み。残るのは実機power-cut HILとFULL attestation
- USB/LAN gateway control transport と logical control messages（**byte-stream framing codec 自体は [19章](19-m3-control-byte-stream-framing.md) の private slice**）
- public Runtime owner wiring / exclusive confinement
- portable conformance subset の on-target 実行
- 上記を含む M3 exit gate
