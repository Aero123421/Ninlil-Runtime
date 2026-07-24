# 20. M3-basic: ESP-IDF clock / entropy / execution adapters

状態: Informative implementation contract（**M3 incomplete**）
対象: ESP-IDF 上の **clock / entropy / execution context** 最小 platform adapters

## 1. この文書の位置付け

本章は [09-roadmap.md](09-roadmap.md) の **M3** のうち、storage / owner-task / Cell Agent より先に閉じられる **基本 platform adapter slice** を固定します。

次を **主張しません**:

- M3 milestone の完了
- ESP-IDF port 全体の完了
- NVS storage port
- FreeRTOS **owner-task body**（scheduler 上の exclusive Runtime owner task）の完成
- USB / LAN gateway、Wi-Fi、SX1262 / radio MAC、Join、application adapter
- public Runtime body / `runtime_create` / `runtime_step` の完成
- 実機 hardware / power-cut HIL 検証の完了
- V1 release の完了

関連境界:

| 文書 | 本章との関係 |
| --- | --- |
| [12-foundation-abi.md](12-foundation-abi.md) | public port vtable shape の正本。**public ABI は変更しない** |
| [14-foundation-ports-and-simulator.md](14-foundation-ports-and-simulator.md) | clock / entropy / execution の portable semantics 正本 |
| [18-m3-prep-esp-idf-component.md](18-m3-prep-esp-idf-component.md) | component packaging / pin。本章は adapter sources をその上へ追加 |
| [07-testing-and-quality.md](07-testing-and-quality.md) | host gate と target compile evidence |

## 2. Public vs port-owned API

| 層 | 場所 | 変更方針 |
| --- | --- | --- |
| Public C ABI | `include/ninlil/*.h` | **変更しない**。`ninlil_clock_ops_t` / `ninlil_entropy_ops_t` / `ninlil_execution_ops_t` をそのまま満たす |
| Port-owned factory | `ports/esp-idf/include/ninlil_esp_idf/*.h` | ESP-IDF 固有の init / caller-owned state 契約。Core public ABI ではない |
| Portable Core sources | `src/model/**` `src/runtime/**` | ESP-IDF / FreeRTOS header を **include しない** |
| ESP-IDF adapter sources | `ports/esp-idf/src/**` | ESP-IDF / FreeRTOS 依存はここだけ |

Port-owned header は `ninlil/platform.h` だけに依存し、`esp_*.h` / `freertos/*` を application に強制しません（実装 `.c` 側が backend を呼びます）。

## 3. 共通実装規則

- C11、例外禁止、VLA 禁止、adapter 内部での heap 動的確保禁止。
- state は **caller-owned** かつ初回 init 前に全体 zero-initialize する（caller precondition）。実装は lifecycle field で live/retired re-init を拒否するが、任意の未初期化 byte 列を検査・正規化して安全な state に変換する API ではない。
- 返却 ops は **immutable**。function pointer / `user` は初回 publish 後、state object の lifetime 終了まで不変。shutdown は active flag だけを retire し ops table を消去しない。
- Runtime が ops を借用する場合は、全 adapter call の完了を待ち `ninlil_runtime_destroy()` を完了してから shutdown、最後に state object の lifetime を終了する。同じ address の新 object は新しい lifetime であり、旧 pointer の使用は契約外。
- Clock / execution は同一 live object の re-init を拒否する one-shot lifecycle。Entropy は同一 boot/process で init 成功または enable 後 cancel の後に再 arm しない boot-global one-shot lifecycle。
- application-specific vocabulary 0。fail-closed。task context only（ISR fail-closed）。
- 実機/HIL 未実証を完了 claim に使わない。CI は esp32s3 **compile/link** 必須。

## 4. Clock adapter（`esp_timer`）

### 4.1 Backend

- 単調時刻源: `esp_timer_get_time()`（boot からの microseconds、同一 boot 内 monotonic）。
- `now_ms = floor(us / 1000)`（checked conversion。負の us は permanent failure）。

### 4.2 Epoch / trust / reboot 境界（仕様先行）

| 規則 | 内容 |
| --- | --- |
| Epoch 供給 | **caller が init 時に non-zero `boot_epoch_id` を供給**。adapter は毎 `now` で random 再生成しない |
| Epoch 寿命 | 1 つの **成功 init 済み** clock instance の間、epoch は不変 |
| Fresh epoch 責任 | **reboot / process restart ごとの fresh `boot_epoch_id` 生成は caller の責任**。adapter は reboot を検知せず、epoch を自動ローテートしない |
| Cross-reboot | `esp_timer` は reboot で 0 に戻る。本 adapter は **reboot 跨ぎ elapsed continuity を証明しない** |
| Epoch 再利用の危険 | 再起動後に **同じ epoch ID を再利用しても TRUSTED の cross-reboot 保証にはならない**。TRUSTED は「現在の esp_timer ドメイン内の boot-local mono」だけを意味する。同一 epoch と見なした Core 比較が reboot 前後で意味を持つことは保証されない（caller contract violation） |
| TRUSTED 根拠 | 同一 boot / 同一成功 init instance 内で `esp_timer` の monotonic 性が backend 契約として使える場合だけ `NINLIL_CLOCK_TRUSTED` を返す。wall clock / NTP / RTC sync を主張しない |
| UNCERTAIN | 本 slice の default path では、証明不能な cross-reboot continuity を **推測して TRUSTED にしない**。reboot 後は **新しい non-zero epoch** を caller が供給して re-init する |
| Same-epoch mono | 同一 epoch で前回成功 sample より小さい `now_ms` を観測したら output を壊さず `NINLIL_PORT_PERMANENT_FAILURE` |
| Invalid out | `out_sample == NULL` または header 不正（`abi_version` / `struct_size`）は `NINLIL_PORT_PERMANENT_FAILURE`、sample 不変（null は trace 不能） |
| Failure 時 | non-OK では caller が用意した sample の remaining fields を success 値で上書きしない |

本 adapter は「deadline 計算に使える **boot-local logical monotonic clock**」であり、wall-clock 表示時刻や reboot 跨ぎ absolute deadline continuity の証明器ではない。

### 4.3 Init publish / one-shot shutdown

| 入力 | 結果 | storage 副作用 |
| --- | --- | --- |
| `clock == NULL` | non-zero | なし |
| `config == NULL` かつ `clock != NULL` | non-zero | なし |
| invalid config（zero epoch / bad header 等）かつ `clock != NULL` | non-zero | なし |
| valid config + zero-init state | 0 | ops を一度だけ publish、`active=1` |
| 同一 object の再 init（active / retired） | non-zero | なし。既存 ops / epoch / sample を変更しない |

shutdown は `active=0, retired=1` にするだけで、既に返した ops table と function pointer / `user` を変更しない。state object が生存する間の retained call は fail-closed。同じ address を allocator が後で再利用する場合、旧 object と全 borrower の lifetime が先に終了していなければならない。

`init` は config を **staged value-copy** する:

1. **ちょうど 4 byte**（`abi_version` + `struct_size`）だけを読む
2. `abi_version` / `struct_size` を検証（full config 未満の short config は **ここで reject**。`boot_epoch_id` を読まない）
3. 十分な `struct_size` のときだけ `boot_epoch_id` を local view へ copy
4. publish は **view の copy** を使う（alias-safe）

Clock だけは staged-copy の検証用として、`config` が zero-init 済み clock storage に一時的に overlay/alias し lifecycle field を変更しない配置を許す。init は config を local view に copy してから ops/state を publish する（pairwise-disjoint は要求しない）。これは任意の未初期化 storage を許可する例外ではない。

### 4.4 Port-owned API（要約）

```text
ninlil_esp_idf_clock_t          caller-owned state
ninlil_esp_idf_clock_config_t   abi header + non-zero boot_epoch_id
ninlil_esp_idf_clock_init(...)  staged validate + one-shot bind; re-init failure is side-effect free
ninlil_esp_idf_clock_ops(...)   non-NULL iff active
```

## 5. Entropy adapter（`esp_fill_random` + ready policy）

### 5.1 Backend と品質境界

- fill backend: `esp_fill_random`（ESP-IDF 5.5.3 public）。
- **品質 claim 禁止:** RF 未起動かつ `bootloader_random_enable` 未実施のまま `esp_fill_random` を production entropy として成功扱いにしない。
- port-owned **explicit policy** が hardware source を arm してからだけ non-zero fill を許可する。

### 5.2 Ready policy / global singleton lifecycle（ESP-IDF 5.5.3 public API）

`bootloader_random_enable` / `bootloader_random_disable` は **process-global** であり、ESP-IDF v5.5.3 では RF/ADC 初期化と同時利用に制約がある。本 port は **component/process あたりちょうど 1 つの live entropy instance** だけが exclusive owner になれる。

| 項目 | 内容 |
| --- | --- |
| Policy | `NINLIL_ESP_IDF_ENTROPY_POLICY_BOOTLOADER_RNG` のみ成功 init を許可 |
| State machine | boot ごとに `FREE → ACQUIRING → OWNED → RELEASING → DISABLING → RETIRED`。enable 後 cancel は `ACQUIRING → DISABLING → RETIRED`。同一 boot で RETIRED から FREE へ戻さない |
| Serialization | ownership / `fill_active` は process-global `portMUX`。`enable`/`disable` は spinlock **外** |
| Release order | RELEASING（drain）→ **DISABLING（owner 保持）** → unlock → `bootloader_random_disable` → re-lock → RETIRED。遅い disable 中も再 acquire を許可しない |
| Concurrent init | ACQUIRING / OWNED / RELEASING / DISABLING / RETIRED 中は fresh address も含め reject |
| ACQUIRING cancel | shutdown(pending) は cancel を記録し、init 側が enable 後に DISABLING へ移して disable/RETIRED を完了するまで shutdown task を通知待機させる。**shutdown 後に当該 instance が live にならない** |
| Drain sync | reserved task-notification index で shutdown task を block。`taskYIELD` polling 禁止。`esp_fill_random` は bounded synchronous backend であり、shutdown task の block が lower-priority fill に実行機会を与える |
| Storage authority | caller は state を zero-init。所有権と boot-global once の authority は global lifecycle registry |
| Immutable ops | storage 内 `ops.fill`/`ops.user` は publish 後 object lifetime 終了まで不変。shutdown は ready flag のみ retire し ops table を memset しない |
| Stale fill | lock 下で owner 一致かつ OWNED を検証。shutdown 後の retained pointer は object が生存中 PERMANENT_FAILURE |
| Same-address reinit / ABA | 同一 boot は global RETIRED が再 init を拒否。reboot 後の旧 pointer は旧 object lifetime 終了済みで使用禁止 |
| Fill | lock 下で OWNED + owner 一致を確認後に `fill_active++`。drain 後 RELEASING→DISABLING |
| ops() 返却 | OWNED storage 内 ops への pointer。shutdown 後も object lifetime 内で pointer / function / user は stable。non-zero fill は fail-closed、zero-length no-op は §5.3 の ABI precedence で OK |
| Threading | **task context only**。**ISR 禁止** → fail-closed |
| RF/ADC | owner は RF/ADC 初期化 **前に** shutdown |
| External owner | application は `bootloader_random_enable/disable` の唯一の process owner が本 adapter であることを保証する。別 component / RF / ADC owner との arbitration は adapter 外の composition contract |
| Notification | `NINLIL_ESP_IDF_ENTROPY_NOTIFY_INDEX` は lifecycle 専用。同じ task の他用途はこの index を使わない |
| Controller | init と matching shutdown は単一 lifecycle controller が直列化する。複数 shutdown caller に完了 barrier を提供しない。`configUSE_TASK_NOTIFICATIONS=1` が必要 |
| Config read | staged（4-byte header → `struct_size` → policy） |

partial fill を success にしない。failure 時に zero / clock / device ID / PRNG fallback で success を捏造しない。

### 5.3 引数 / status

| 入力 | status | 副作用 |
| --- | --- | --- |
| `length == 0` | `NINLIL_PORT_OK` | out を dereference しない（ready 不要） |
| not exclusive-ready && `length>0` | `NINLIL_PORT_PERMANENT_FAILURE` | backend 0 |
| `length > 0 && out == NULL` | `NINLIL_PORT_PERMANENT_FAILURE` | write 0 |
| uninitialized / null user | `NINLIL_PORT_PERMANENT_FAILURE` | write 0 |
| exclusive ready + valid non-zero | `esp_fill_random` 後 `NINLIL_PORT_OK` | full write |

### 5.4 Port-owned API（要約）

```text
ninlil_esp_idf_entropy_config_t   header + policy
ninlil_esp_idf_entropy_init(...)  exclusive acquire + enable (reject live re-init)
ninlil_esp_idf_entropy_is_ready(...)  owner+ready only
ninlil_esp_idf_entropy_shutdown(...)  owner-only disable + retire（ops は不変）
ninlil_esp_idf_entropy_ops(...)  owner only
```

## 6. Execution context adapter（FreeRTOS task identity）

### 6.1 Backend

- task context: `xTaskGetCurrentTaskHandle()` の `TaskHandle_t` を identity 素材とする。
- **ISR fail-closed:** `xPortInIsrContext()` が非 zero のとき **handle を取らず identity `0`**（interrupted task を owner に偽装しない）。
- owner-task **confinement に使える identity** を提供する。
- **owner task 本体** は **本章の完成 claim 対象外**。

### 6.2 `TaskHandle_t` → `uint64_t` 規則（静的）

| 規則 | 内容 |
| --- | --- |
| 幅 | `sizeof(TaskHandle_t) <= sizeof(uint64_t)` を compile-time に固定（static assert）。超過 target は build 失敗 |
| 変換 | `(uint64_t)(uintptr_t)handle`（ゼロ拡張。比較用途のみ） |
| NULL | handle が NULL のとき `0` |
| ISR | `xPortInIsrContext()` → 必ず `0` |
| Adapter lifecycle | zero-init object へ一度だけ publish。同一 live/retired object の re-init は拒否。shutdown 後の retained call は object lifetime 内で `0` |
| TaskHandle reuse | identity を保持する側は対象 task の delete 完了前に owner binding を破棄する。delete 後に raw handle address が再利用される可能性があり、task lifetime を跨ぐ比較は禁止 |
| 意味 | 値は **比較専用** |

### 6.3 Port-owned API（要約）

```text
ninlil_esp_idf_execution_t
ninlil_esp_idf_execution_init(...)
ninlil_esp_idf_execution_ops(...)  → current_context_id (ISR→0)
```

## 7. Source authority 分離

| Authority ファイル | 内容 |
| --- | --- |
| `cmake/ninlil_runtime_private_sources.cmake` | portable Core / private Runtime のみ（従来どおり） |
| `cmake/ninlil_esp_idf_port_sources.cmake` | ESP-IDF adapter + host-testable pure logic の **port-owned** source list |

規則:

- portable authority に `ports/esp-idf/**` を入れない。
- ESP-IDF / FreeRTOS header を portable `src/**` へ入れない。
- pure logic（invalid argument / conversion / mono boundary）は ESP header 非依存とし、host CTest で検査できる。
- component は両方の authority を include し、`file(GLOB)` しない。

## 8. 検証

| 層 | Evidence |
| --- | --- |
| Host pure unit | short config、alias、ISR `in_isr`、entropy not-ready、**singleton lifecycle**（二重 init / non-owner shutdown / live re-init） |
| Host packaging gate | source authority 分離、pin、no GLOB、portable に ESP include なし |
| Target CI smoke | `.github/workflows/esp-idf.yml` が公式 image で **esp32s3 の compile/link build**（`idf.py ... build`）。**device 実行 / HIL / 実機 1-call 実行は workflow の証拠ではない** |
| Smoke source role | `ports/esp-idf/smoke_app` は 3 adapter の type/link 用 firmware project。ソース上の init/fill 呼び出しは **build 対象の契約 fixture** であり、CI は実行結果を gate しない |

Host は ESP-IDF を install しない。target 実動作（RNG 品質、timer drift、ISR 実機、RF 併存、HIL）は **未実証**。

## 9. Acceptance（本 slice のみ）

- [x] clock staged header read + alias-safe + live/retired re-init reject（既存 state 不変）
- [x] execution ISR → identity 0
- [x] entropy exclusive singleton + live re-init reject without destroy + owner-only shutdown
- [x] host negatives fixed; packaging gate; public ABI 非変更
- [x] host Debug + ASan + tests-OFF + `git diff --check`
- [x] docs が CI smoke を compile/link と正確記載（実行 HIL を claim しない）
- [x] M3 / NVS / owner-task body / HIL / V1 完了を主張しない

## 10. 明示的に残る / 後続の M3 work

- FreeRTOS owner-task body / Cell Agent skeleton / loopback TxPermit は [22章](22-m3-owner-cell-agent-skeleton.md) の別 slice（本章の完了 claim には含めない）
- NVS / partition storage port と power-cut HIL
- USB/LAN control transport driver と logical control messages
- public Runtime body との owner wiring
- POSIX と同一 portable conformance subset の on-target 実行
- 上記を含む M3 exit gate
