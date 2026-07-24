# Ninlil ESP-IDF component (M3-prep + M3-basic + owner/cell + storage + U2 CDC + R4 SX1262 control-plane + R5 LAB_ONLY profile packaging candidate)

この directory は、実装済みの **portable Core / private Runtime library** を ESP-IDF component として ESP32-S3 向けに **compile** し、加えて **M3-basic**（clock / entropy / execution）、**experimental M3 owner-task / Cell Agent / loopback TxPermit**（docs/22）、**format 4 dual-slot durable-storage candidate**（docs/21）、**U2 A2 USB CDC-ACM adapter candidate**（docs/23）、**R4 SX1262 control-plane portable + ESP SPI/GPIO bus candidate**（docs/28）、および **R5 LAB_ONLY private profile_loader / PCP bind packaging candidate**（docs/29; private sources only）を port 向けに提供します。

**実装済み（experimental / candidate packaging）:** owner-task + FreeRTOS queue/notify、Cell Agent assignment、loopback TxPermit、durable-storage flash bind / host conformance、U2 control CDC adapter candidate（`esp_tinyusb==2.1.1`）、R4 SX1262 control-plane（reset/init/SPI allowlist + STDBY_RC; SetTx 構造的不在; ESP SPI/GPIO bus）、R5 private LAB_ONLY profile_loader + R1/R2/R3 radio private sources の component 収録、combined smoke self-test **source**（dual-core + real ISR timer config + storage COMMIT_UNKNOWN + CDC **init CLOSED snapshot** — no USB install/open in smoke）。

**これは M3 の部分 slice + U2/R4/R5 packaging candidate です。** 次を提供・主張しません。

- storage の実機 FULL attestation / power-cut HIL PASS
- **U2 Required HIL**（実機 flash + host CDC 往復 + DTR down/up old-generation payload negative）/ USB series complete
- TinyUSB complete TX/RX FIFO purge or recall of endpoint/hardware-in-flight / already-transmitted bytes（U2 は Ninlil ring generation isolation + software FIFO soft-clear のみ）
- **SX1262 physical RF TX/RX、SetTx path、radio MAC、production radio / legal / HIL**（R4 は control-plane candidate のみ; compile ≠ RF complete）
- **R5 complete / FIELD / PRODUCTION / Japan legal / RF / HIL**（LAB_ONLY host/ESP packaging candidate のみ）
- Wi-Fi、Join、product-specific adapter
- public Runtime の production 実行経路
- **compile/link を HIL PASS / dual-core race PASS とみなすこと**
- PSRAM workspace の caller 所有や二重bind許可
- M3 complete、ESP-IDF port complete、hardware verified、V1 complete

仕様と pin の正本:

- packaging: [docs/18-m3-prep-esp-idf-component.md](../../docs/18-m3-prep-esp-idf-component.md)
- basic adapters: [docs/20-m3-basic-esp-idf-platform-adapters.md](../../docs/20-m3-basic-esp-idf-platform-adapters.md)
- owner/cell/loopback: [docs/22-m3-owner-cell-agent-skeleton.md](../../docs/22-m3-owner-cell-agent-skeleton.md)
- durable storage: [docs/21-m3-esp-idf-durable-storage.md](../../docs/21-m3-esp-idf-durable-storage.md)
- USB CDC / radio boundary (U0–U2): [docs/23-usb-radio-boundary.md](../../docs/23-usb-radio-boundary.md)
- R4 SX1262 control-plane: [docs/28-r4-sx1262-control-plane-backend.md](../../docs/28-r4-sx1262-control-plane-backend.md) / [ADR-0008](../../docs/adr/0008-r4-sx1262-control-plane-backend.md)
- R5 LAB_ONLY profile loader + permit bind: [docs/29-r5-lab-only-profile-loader.md](../../docs/29-r5-lab-only-profile-loader.md) / [ADR-0009](../../docs/adr/0009-r5-lab-only-profile-loader.md)

## Pinned ESP-IDF version

```text
ports/esp-idf/ESP_IDF_VERSION  →  v5.5.3
```

- 公式 Docker image: `espressif/idf:v5.5.3`
- Component Manager: `idf.version: "==5.5.3"` + **`espressif/esp_tinyusb: "==2.1.1"`**（U2; `components/ninlil/idf_component.yml`）
- Committed locks: `smoke_app/dependencies.lock` + `hil_app/dependencies.lock`（**do not commit `managed_components/`**）
- 必須 build target: **`esp32s3`**

この pin は「最新 stable の自動追従」ではなく、M3-prep / M3-basic / U2 の **再現可能な既知安定版** です。変更する場合は `ESP_IDF_VERSION`・docs・CI・`idf_component.yml`・locks を同一変更で揃えてください。

## Layout

| Path | Role |
| --- | --- |
| `components/ninlil/` | `idf_component_register` された component |
| `include/ninlil_esp_idf/` | port-owned factory headers（public Core ABI ではない） |
| `src/` | pure logic + ESP-IDF backend adapters |
| `smoke_app/` | basic adapters・Owner/Cell/loopback・storage candidateを同時検査するcombined firmware project |
| `ESP_IDF_VERSION` | concrete version pin |
| `../../cmake/ninlil_runtime_private_sources.cmake` | portable private source list 正本 |
| `../../cmake/ninlil_esp_idf_port_sources.cmake` | ESP-IDF port source list 正本 |
| `../../cmake/ninlil_esp_storage_sources.cmake` | durable-storage target/host source list正本 |
| `../../include/ninlil/` | public headers |
| `../../src/model/` `../../src/runtime/` | portable private sources |

## Port-owned basic adapters

`include/ninlil` public ABI は変更しません。次の port-owned headers が `ninlil_*_ops_t` を満たす factory を提供します。

| Header | Backend | Notes |
| --- | --- | --- |
| `ninlil_esp_idf/clock.h` | `esp_timer` + **immutable embedded ops** | zero-init one-shot。boot-local TRUSTED。reboot ごと fresh epoch は caller 責任 |
| `ninlil_esp_idf/entropy.h` | `esp_fill_random` + bootloader RNG | boot-global one-shot + DISABLING + **reserved task-notification drain** + ACQUIRING cancel/await |
| `ninlil_esp_idf/execution.h` | FreeRTOS task handle + immutable embedded ops | zero-init one-shot、ISR→0。TaskHandle identity は task delete を跨いで保持しない |
| `ninlil_esp_idf/owner_task.h` | opaque API | inflight + claim + start barrier + JOIN_ACK（docs/22） |
| `ninlil_esp_idf/owner_task_storage.h` | concrete FreeRTOS | `StackType_t` stack、ESP app include |
| `ninlil_esp_idf/cell_agent.h` / `cell_agent_storage.h` | skeleton | tx_gate idle atomic swap |
| `ninlil_esp_idf/loopback_tx_permit.h` | `ninlil_tx_gate_ops_t` | deny-by-default; logical_bytes>0; live shutdown fail |

state は caller-owned（static 可）で初回 init 前に全体 zero-initialize します。返却 ops を Runtime が借用する場合は、全 call を quiesce して `ninlil_runtime_destroy()` を完了した後に adapter を shutdown し、最後に state lifetime を終了します。heap / VLA / exception を使いません。

### 最小利用例

```c
#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/execution.h"

static ninlil_esp_idf_clock_t clock_state;
static ninlil_esp_idf_entropy_t entropy_state;
static ninlil_esp_idf_execution_t execution_state;

void setup_ports(void)
{
    ninlil_esp_idf_clock_config_t clock_cfg = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = (uint16_t)sizeof(clock_cfg),
        .boot_epoch_id = {{0xe5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01}},
    };
    ninlil_esp_idf_entropy_config_t entropy_cfg = {
        .abi_version = NINLIL_ABI_VERSION,
        .struct_size = (uint16_t)sizeof(entropy_cfg),
        .policy = NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG,
    };
    (void)ninlil_esp_idf_clock_init(&clock_state, &clock_cfg);
    /* Exclusive process singleton: only one live entropy owner. */
    (void)ninlil_esp_idf_entropy_init(&entropy_state, &entropy_cfg);
    (void)ninlil_esp_idf_execution_init(&execution_state);
    /* ninlil_esp_idf_*_ops(&...) → ninlil_platform_ops_t fields */
    /* Before RF/ADC init: ninlil_esp_idf_entropy_shutdown(&entropy_state); */
}
```

**Entropy 注意（ESP-IDF v5.5.3）:** process-global RNG + `portMUX`。同一 boot は `... → DISABLING → RETIRED` の一回限りで、fresh address でも再 init しません。単一 lifecycle controller が init/shutdown を直列化します。ACQUIRING cancel と fill drain は `NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX` を専用利用して shutdown task を block します（task notification 有効が必要）。ops は state 内で immutable（shutdown で fill/user を消去しない）。本 adapter 以外の RNG/RF/ADC owner は application が排他調停し、RF/ADC 前に `shutdown` します。**task only**。

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

### 3. headers

```c
#include "ninlil/version.h"
#include "ninlil/runtime.h"
#include "ninlil/platform.h"
#include "ninlil_esp_idf/clock.h"
#include "ninlil_esp_idf/entropy.h"
#include "ninlil_esp_idf/execution.h"
```

private header（`src/model/*`、`src/runtime/*`、`ports/esp-idf/src/*`）を application から include しないでください。

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

host の `ninlil_runtime_private` と本 component の portable 部分は、同じ

`cmake/ninlil_runtime_private_sources.cmake`

を `include` します。ESP-IDF adapters は

`cmake/ninlil_esp_idf_port_sources.cmake`

が正本です。durable storage は

`cmake/ninlil_esp_storage_sources.cmake`

が正本です。`file(GLOB)` は使いません。host CTest の `esp_idf_component_packaging_gate` と `esp_idf_port_logic` が pin / authority / pure logic を検査します。

## 次に必要な M3 本体（本 candidate の非主張）

- storageの実機power-cut HILとFULL attestation
- USB/LAN control transport と logical control messages（byte-stream framing の private `NCG1` codec は [docs/19](../../docs/19-m3-control-byte-stream-framing.md)）
- public Runtime owner wiring / exclusive Runtime confinement
- portable conformance subset の on-target 実行
