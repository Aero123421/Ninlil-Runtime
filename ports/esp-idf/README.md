# Ninlil ESP-IDF component (M3-prep)

この directory は、実装済みの **portable Core / private Runtime library** を ESP-IDF component として ESP32-S3 向けに **compile** するための packaging です。

**これは M3-prep です。** 次を提供・主張しません。

- ESP-IDF storage (NVS) / FreeRTOS owner task / USB / Wi-Fi / SX1262
- radio MAC、Join、KGuard adapter
- public Runtime の production 実行経路
- M3 complete、ESP-IDF port complete、hardware verified、V1 complete

仕様と pin の正本: [docs/18-m3-prep-esp-idf-component.md](../../docs/18-m3-prep-esp-idf-component.md)

## Pinned ESP-IDF version

```text
ports/esp-idf/ESP_IDF_VERSION  →  v5.5.3
```

- 公式 Docker image: `espressif/idf:v5.5.3`
- Component Manager: `idf.version: "==5.5.3"`（`components/ninlil/idf_component.yml`）
- 必須 build target: **`esp32s3`**

この pin は「最新 stable の自動追従」ではなく、M3-prep の **再現可能な既知安定版** です。変更する場合は `ESP_IDF_VERSION`・docs・CI・`idf_component.yml` を同一変更で揃えてください。

## Layout

| Path | Role |
| --- | --- |
| `components/ninlil/` | `idf_component_register` された component |
| `smoke_app/` | component を link する最小 firmware project |
| `ESP_IDF_VERSION` | concrete version pin |
| `../../cmake/ninlil_runtime_private_sources.cmake` | host と共有する source list 正本 |
| `../../include/ninlil/` | public headers |
| `../../src/model/` `../../src/runtime/` | portable private sources |

## 自 project への導入例

### 1. EXTRA_COMPONENT_DIRS

Ninlil repository を clone したうえで、自 firmware の最上位 `CMakeLists.txt` より前に:

```cmake
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/path/to/ninlil/ports/esp-idf/components"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_firmware)
```

### 2. app から require

```cmake
# main/CMakeLists.txt
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES ninlil
)
```

### 3. public header だけを include

```c
#include "ninlil/version.h"
#include "ninlil/runtime.h"
#include "ninlil/platform.h"

void app_main(void)
{
    /* Public ABI types/constants are available.
     * Public Runtime function bodies and ESP-IDF ports are not complete. */
    (void)NINLIL_ABI_VERSION;
}
```

private header（`src/model/*`、`src/runtime/*`）を application から include しないでください。

### 4. Build

```sh
# ESP-IDF v5.5.3 の環境を export した shell で:
idf.py set-target esp32s3
idf.py build
```

## Repository 内 smoke app

```sh
# 公式 Docker（host へ ESP-IDF を入れない場合）
pin="$(tr -d '[:space:]' < ports/esp-idf/ESP_IDF_VERSION)"
docker run --rm -v "$PWD:/project" -w /project "espressif/idf:${pin}" \
  bash -lc '. $IDF_PATH/export.sh && idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build'
```

```sh
# 既に IDF_PATH=v5.5.3 がある場合
. "$IDF_PATH/export.sh"
idf.py -C ports/esp-idf/smoke_app set-target esp32s3 build
```

## Source list drift

host の `ninlil_runtime_private` と本 component は、同じ

`cmake/ninlil_runtime_private_sources.cmake`

を `include` します。`file(GLOB)` は使いません。host CTest の `esp_idf_component_packaging_gate` が pin と authority の一致を検査します。

## 次に必要な M3 本体（未実装）

- FreeRTOS owner-task adapter
- NVS / partition storage port と power-cut HIL
- clock / entropy / execution の ESP-IDF port
- Cell Agent skeleton、USB/LAN control transport
- portable conformance subset の on-target 実行
