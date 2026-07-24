# V1-LAB ESP platform provider matrix (P1-2)

作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`  
正本 catalog: `include/ninlil/platform.h` `ninlil_platform_ops_t`（8 slots）  
検証: `tests/port/v1_esp_provider_availability_test.c` / `ninlil_esp_idf/platform_availability.h`

凡例:

| Status | 意味 |
| --- | --- |
| **implemented** | ESP-IDF port factory + host 検証あり。Runtime init で ops 必須（storage は FULL success 禁止は別 gate） |
| **LAB unavailable** | V1 LAB では factory なし。init/admission で明示 `NINLIL_PORT_PERMANENT_FAILURE` / platform wiring reject（stub success 禁止） |
| **V2** | V1 スコープ外 |

## Matrix（`ninlil_platform_ops_t`）

| Provider | Status | Factory / init | Ownership | Shutdown | Restart | Fault / negative test | Target link |
| --- | --- | --- | --- | --- | --- | --- | --- |
| allocator | **LAB unavailable** | なし（`ninlil_esp_idf_provider_admission_request` → `PERMANENT_FAILURE`） | — | — | — | `v1_esp_provider_availability` stub reject | — |
| execution | **implemented** | `ninlil_esp_idf_execution_init` | caller-owned `ninlil_esp_idf_execution_t` | lifecycle retire（ops 不変） | 同一 object re-init 拒否 | `esp_idf_port_logic` ISR/one-shot | `smoke_app` ELF |
| clock | **implemented** | `ninlil_esp_idf_clock_init` | caller-owned `ninlil_esp_idf_clock_t` | `ninlil_esp_idf_clock_shutdown` 相当 | reboot 後 fresh epoch は caller | `esp_idf_port_logic` mono/short-config | `smoke_app` ELF |
| entropy | **implemented** | `ninlil_esp_idf_entropy_init` | boot-global one-shot | `ninlil_esp_idf_entropy_shutdown` | 同一 boot 再 init 拒否 | `esp_idf_port_logic` lifecycle | `smoke_app` ELF |
| storage | **implemented**（**FULL OK 禁止**） | `ninlil_port_esp_storage_flash_bind`（`FULL_ESP_UNPROVEN` 固定） | PSRAM workspace（binder 所有） | `ninlil_port_esp_storage_flash_unbind` | `open` media reload; COMMIT_UNKNOWN fence | `esp_storage_dual_slot_conformance` + `v1_esp_durable_success_*` gate | `smoke_app` + `hil_app` ELF/map |
| bearer | **LAB unavailable** | なし | — | — | — | `v1_esp_provider_availability` admission reject | — |
| tx_gate | **implemented** | `ninlil_esp_idf_loopback_tx_permit_init` | caller-owned `ninlil_esp_idf_loopback_tx_permit_t` | deny-by-default idle | shutdown fail-closed | `owner_cell_agent_logic` lease/registry | `smoke_app` ELF |
| origin_authorization | **LAB unavailable** | なし | — | — | — | `v1_esp_provider_availability` admission reject | — |

## Storage 追加制約（P0-5 / docs/26 §9.4）

| 経路 | HIL attestation なし build |
| --- | --- |
| `commit(FULL)` | 常に `NINLIL_STORAGE_COMMIT_UNKNOWN`（ESP target source） |
| readback 一致後の再 commit | **STORAGE_OK へ昇格しない**（`test_esp_unproven_readback_match_no_success_promotion`） |
| custody ACCEPT / payload release | transport 層（項目 8+）— storage gate は dual-slot success symbol 0 |

## 関連 ESP port（platform_ops 外・参考）

| Component | Status | Notes |
| --- | --- | --- |
| owner_task / cell_agent | implemented（experimental） | docs/22 skeleton; `owner_cell_agent_logic` |
| USB CDC (U2) | implemented（candidate） | `esp_usb_cdc_u2_logic`; smoke init CLOSED snapshot |
| SX1262 bus (R4) | implemented（control-plane candidate） | `sx1262_r4_test`; RF/HIL 非 claim |

## LAB unavailable 受入（test 実証）

`ninlil_esp_idf_provider_admission_request` は LAB unavailable catalog 行に対し、ops 非 NULL でも **常に** `NINLIL_PORT_PERMANENT_FAILURE` を返す（stub success 0）。

`ninlil_esp_idf_platform_ops_admit` は `allocator` / `bearer` / `origin_authorization` の非 NULL wiring を拒否する。
