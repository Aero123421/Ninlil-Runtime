# 28. R4 SX1262 Control-Plane Backend（reset / init / SPI only）

状態: **Normative for R4 host control-plane implementation candidate**（physical RF TX/RX **未実装**; **R4 complete / production radio / RF / legal / HIL / Japan profile ではない**）<br>
対象: D1 SX1262 backend の **reset / init / SPI control-plane** と fail-closed TX deny<br>
依存: [05](05-security-and-compliance.md)、[07](07-testing-and-quality.md)、[09](09-roadmap.md)、[18](18-m3-prep-esp-idf-component.md)、[20](20-m3-basic-esp-idf-platform-adapters.md)、[23](23-usb-radio-boundary.md) §9 / §10.2、[ADR-0003](adr/0003-radio-usb-dependency-direction.md)、[ADR-0008](adr/0008-r4-sx1262-control-plane-backend.md)、R1 `src/radio/radio_hal.h`<br>
非対象: R2 authority body、R3 airtime、R5 profile loader、R6/R7 wire、R9 SPI TX sole-edge 完成、R10 HIL、Japan 数値、legal certification、public ABI、KGuard、RadioLib、physical RF emission<br>
番号: **docs/28 + ADR-0008**（docs/25–26 / ADR-0005–0006 は U5/U6 予約、docs/27 / ADR-0007 は R3 予約 — 衝突禁止）

## 0. 読み順

1. §1 非主張 / Forbidden claims
2. [ADR-0008](adr/0008-r4-sx1262-control-plane-backend.md)
3. 本章 §2–§12
4. R1 `radio_hal.h`（sole TX edge は H1; R4 は D1 control-plane）
5. §13 vectors / gates / Required HIL blockers

矛盾時: Accepted ADR > 本章 > docs/23 §10.2 R4 行 > 実装 header。

---

## 1. 位置付け・非主張

### 1.1 本 slice が閉じること

| ID | 内容 |
| --- | --- |
| R4-N1 | portable D1 control-plane API + lifecycle（heap/VLA 禁止、C11） |
| R4-N2 | board wiring config 必須（pin 役割 + optional flags + timing fields）; 矛盾/未設定は init 前 reject |
| R4-N3 | abstract bus ops（reset / BUSY / SPI / delay / now）; ESP-IDF 型を portable に漏らさない |
| R4-N4 | hard reset + BUSY wait + allowlisted SPI + **STDBY_RC** で init 完了 |
| R4-N5 | TX 要求は **explicit deny**、SetTx SPI 0、payload/buffer 書込 0 |
| R4-N6 | production sources から SetTx / SetRx / CW / infinite-preamble / RadioLib transmit / alternate TX symbol を構造的に排除（ban + gate） |
| R4-N7 | single-owner / re-entry / wrong-state fail-closed; partial init rollback |
| R4-N8 | host bus spy + fault injection + exact unit tests + structural gate |
| R4-N9 | tests-OFF private archive に spy/oracle/fixture 非混入 |
| R4-N10 | public `include/ninlil` ABI 非変更 |

### 1.2 Forbidden claims（MUST NOT）

- R4 complete / production radio complete / SX1262 production TX complete
- physical RF TX / RX / CAD / CW 動作
- R1 series complete の代替主張
- R2 Physical Compliance Permit authority 実装完了
- R9 sole SPI TX edge 完成
- Japan production RegulatoryProfile 数値 / legal certification / RF HIL PASS
- `compile == HIL` / esp32s3 link 成功 = RF 動作
- Seeed / XIAO pin を portable 既定とする主張
- public ABI 昇格

### 1.3 用語

| 語 | 意味 |
| --- | --- |
| D1 | SX1262 control-plane backend（本章） |
| H1 | R1 `ninlil_radio_hal` sole transmit-with-permit（別 slice） |
| bus ops | portable 抽象; 物理 SPI/GPIO 実装は port |
| board config | pin 役割 + optional features + timing budgets |
| allowlist | init/control で **送ってよい** opcode 集合 |
| banlist | production が **送ってはならない** opcode 集合（RF emission 含む） |
| STDBY_RC | chip mode standby RC（安全な制御平面終端） |

---

## 2. 配置と依存（compile / runtime）

### 2.1 置き場所（MUST）

| 層 | 場所 | 依存してよい | 依存禁止 |
| --- | --- | --- | --- |
| Portable D1 | `drivers/sx126x/*` | C11、自身の header | ESP-IDF、FreeRTOS、`spi_*.h`、termios、TinyUSB、RadioLib、KGuard、`include/ninlil` への型露出 |
| Host bus spy | `tests/support/*` | D1 header | production archive への登録 |
| ESP bus adapter | `ports/esp-idf/**` | ESP-IDF pin 済み API、D1 bus ops | portable Core への ESP 型逆流、R4 での RF TX |
| Source authority | `cmake/ninlil_sx1262_sources.cmake` | explicit path list | `file(GLOB)` |

### 2.2 Runtime と H1 の関係（MUST）

```text
R4 時点:
  H1 edge callback は未配線のまま default-deny 可能
  D1 は control-plane init のみ提供
  D1 は H1 の代替 sole TX 入口を提供しない

後続 R9:
  H1 transmit-with-permit success 後の edge だけが
  D1 の（将来）TX SPI path に到達し得る
```

R4 は H1 を完成させない。R4 は R2 を完成させない。

### 2.3 Public ABI（MUST NOT）

`include/ninlil/*.h` に SX1262 / SPI / pin / radio backend 型を追加しない（別 ADR なし）。

---

## 3. Primary sources（MUST pin）

### 3.0 一次資料集合（本 slice 正本）

| 文書 | 識別 | 用途 |
| --- | --- | --- |
| **Datasheet** | Semtech **DS.SX1261-2.W.APP Rev 2.2 Dec 2024** | reset / BUSY TSW / TCXO delay step / regulator / status / device errors; **§9.2.1** TCXO 時 image cal 失敗 |
| **Driver** | Semtech **sx126x_driver v2.3.2** commit `9636dc4660ada4eeddf91eb7b3f7f241000bf202` | opcode / status mask / CAL_ALL / errors mask |
| **Official app** | Semtech **SWSD003 v2.3.0** commit `5cf9794ea62edd092025ea437353db820df6c796`（`sx126x_hal.c` reset `LL_mDelay(1)` = **1ms**; `apps_common.c` Dio3→Cal ALL） |

**MUST:** DS Rev2.2 を一次根拠として数値を pin する（曖昧化禁止）。
**MUST NOT:** HIL 未実施 / board 実測未を DS 引用で置き換えること。

### 3.1 Opcode / status / errors（閉じた集合）

| 項目 | 値 | 出典 |
| --- | --- | --- |
| GetStatus | `0xC0` | driver Commands Interface |
| SetStandby | `0x80` | driver |
| GetDeviceErrors | `0x17` | driver |
| ClearDeviceErrors | `0x07` | driver |
| SetRegulatorMode | `0x96` | driver; DS §13.1.11 p80 |
| Calibrate | `0x89` | driver; DS §13.1.12; TCXO path CAL_ALL |
| SetDio2AsRfSwitchCtrl | `0x9D` | driver |
| SetDio3AsTcxoCtrl | `0x97` | driver; DS §13.3.6 delay(23:0) |
| **SetTx 禁止** | `0x83` | banlist only |
| **SetRx 禁止** | `0x82` | banlist only |
| chip mode pos/mask | pos=4, `0x07<<4` | driver |
| STBY_RC | `2` | driver |
| cmd_status pos/mask | pos=1, `0x07<<1` | driver |
| cmd_status fail set | `{3,4,5}` = timeout / process error / exec failure | driver `sx126x_cmd_status_e` |
| XOSC_START_ERR | `1<<5` | driver `SX126X_ERRORS_XOSC_START` |
| IMG_CALIB_ERR | `1<<4` | driver `SX126X_ERRORS_IMG_CALIBRATION` |
| **TCXO cold expected mask** | `XOSC_START_ERR \| IMG_CALIB_ERR` | DS **§9.2.1**: TCXO 時 32MHz 未確立で **image calibration が失敗し得る**; clear 後 SetDIO3→CAL_ALL |
| CAL_ALL | `0x7F` bits 0..6 | driver `SX126X_CAL_ALL` |
| REG LDO / DC-DC | `0x00` / `0x01` | driver; DS §5 / §13.1.11 |
| TCXO delay step | **15.625 µs / step** | DS delay(23:0) |
| NRESET（DS 記述） | typically 100 µs | DS §8.1 — **R4 の保証 minimum ではない** |
| NRESET（R4 採用） | **1000 µs (1ms)** | SWSD003 `sx126x_hal_reset` `LL_mDelay(1)` |
| BUSY rise max after NSS↑ | **600 ns** | DS TSW |
| SPI で SX1261/2 識別 | **不能** | DS; R4 は SKU 主張禁止 |

**MUST:** allowlist 外 opcode の SPI 送信 0。
**MUST NOT:** RadioLib を正本にする。
**MUST NOT:** `CHIP_MISMATCH` という **SKU/型番確認** を SPI status だけで主張する（status/mode **invalid** として扱う）。

### 3.2 Board timing fields（別契約; 流用禁止）

| field | 単位 | 規則 | 出典 / 注 |
| --- | --- | --- | --- |
| `reset_pulse_us` | µs | **R4 必須 = 1000**（SWSD003 1ms 採用） | DS「typically 100µs」は **保証 minimum と主張しない**。R4 は公式 example 1ms を固定 |
| `busy_timeout_ms` | ms | non-zero; reset 後 / 長待ち | host watchdog; HIL 実測未は非主張 |
| `spi_busy_timeout_ms` | ms | non-zero; command 前後 BUSY low 待ち | host watchdog |
| `post_spi_busy_guard_us` | µs | **≥ 1**（≥600ns をカバーする整数 µs） | DS TSW max 600ns; 即時 low 判定禁止 |
| `tcxo_delay_rtc_steps` | step | TCXO_PRESENT 時 **nonzero** かつ **24-bit** `1..0xFFFFFF`（0 は reject）; **ms と混同禁止** | DS delay(23:0)×15.625µs |
| `tcxo_busy_timeout_ms` | ms | TCXO 時必須 non-zero; Dio3/Calibrate 後 BUSY 待ち | **steps とは別 field** |
| `regulator_mode` | enum | **LDO または DC-DC のみ; 未指定 reject** | DS §5 p31 / §13.1.11 p80; apps_common 明示 |

### 3.3 Host test vs production board

| profile | 言えること | 言えないこと |
| --- | --- | --- |
| host spy | allowlist / 順序 / fault / delayed BUSY | board 実測 timing 適合 / HIL |
| ESP board config | wiring + 明示 profile 値 | Seeed を Core 既定; RF HIL PASS |

---

## 4. Board wiring config（MUST）

### 4.1 必須 pin 役割

| 役割 | 必須 | 説明 |
| --- | --- | --- |
| NSS | yes | SPI chip select |
| SCK | yes | SPI clock |
| MOSI | yes | SPI host→device |
| MISO | yes | SPI device→host |
| RESET | yes | NRESET |
| BUSY | yes | BUSY |
| DIO1 | yes | IRQ line（R4 は poll しないが wiring 完全性のため必須宣言） |
| ANT_SW | no* | 外部 RF switch GPIO。board が外部 switch を持つなら必須 |

\* `feature_flags` の `ANT_SW_PRESENT` が set のとき ANT_SW pin 必須。unset なら pin は **unset sentinel** でなければならない（矛盾 reject）。

### 4.2 Optional features / required closed fields

| flag / field | 意味 | 追加必須 |
| --- | --- | --- |
| `TCXO_PRESENT` | DIO3 TCXO + **Calibrate(ALL=0x7F)** | `tcxo_delay_rtc_steps` **nonzero**（24-bit）、`tcxo_busy_timeout_ms`、`tcxo_voltage`、`vdd_op_mv`（**VDDop > VTCXO+200mV**） |
| `DIO2_RF_SWITCH` | DIO2 を **RF switch 専用** 一線制御（**DIO1 IRQ と非共用**） | board が DIO2 を RF switch に使うときのみ |
| `ANT_SW_PRESENT` | 外部 ANT_SW GPIO | pin ≠ UNSET・必須 pin と **重複禁止**; `ant_sw_set` non-NULL; init 成功後 **安全初期 level=inactive(0)** を callback で設定。flag 無し時 pin=UNSET かつ `ant_sw_set==NULL`（未使用 callback 禁止） |
| `regulator_mode` | **常に必須** LDO(`0`) / DC-DC(`1`) | 他値・未指定 reject |
| `reserved0` / `reserved_zero` | 予約 | **必須 0** |

### 4.2.1 Board pin 正本（portable vs ESP composition）

| 層 | 表現 | 正本 |
| --- | --- | --- |
| **portable D1 `board_config`** | opaque `uint32_t` pin id | **board wiring の唯一の意味論的正本**（D1 が検証） |
| ESP `bus_config` | 実 GPIO 番号 | **port 写像結果のみ** — 独自の board 意味を持たない |
| composition | board profile → portable ids **と** ESP GPIOs を **同一 profile から生成** | 不一致は composition bug（D1/port は相手の型を知らない） |

**MUST NOT:** portable と ESP に別々の pin 表を持ち「どちらが正しいか」を二系統で主張する。
**MUST:** 単一 board profile が opaque id と ESP GPIO を同時に定義し、composition が両方を埋める。

### 4.3 Pin 表現（portable）

Portable config は **board-local opaque `uint32_t` pin id** を持つ。

- `NINLIL_SX1262_PIN_UNSET = 0xFFFFFFFFu` を未設定 sentinel とする。
- ESP adapter が `gpio_num_t` へ写像する。portable は GPIO 番号空間を仮定しない。
- **Seeed / XIAO の具体番号を portable 既定値にしない。** example board table は docs の Informative に限り、Core に embed しない。

### 4.4 検証（init 前; MUST; exact order）

1. `backend == NULL` / `config == NULL` / `bus_ops == NULL` → INVALID_ARGUMENT、副作用 0
2. config header（`abi_version` / `struct_size`）staged 検証
3. 必須 pin がすべて UNSET でない
4. 必須 pin 同士がすべて distinct
5. optional flag と pin/timeout の整合（flag on → 必須値が non-zero / non-UNSET; flag off → 対応 optional が UNSET/0）
6. timing 必須フィールド non-zero
7. `reserved_zero == 0`
8. bus ops 必須関数ポインタ non-NULL（`reset_assert` / `reset_deassert` / `busy_is_high` / `spi_transfer` / `delay_us` / `now_ms`）
9. optional `ant_sw_set` は `ANT_SW_PRESENT` のときのみ non-NULL 必須

いずれか失敗 → **bus を呼ばない**。

---

## 5. Lifecycle / concurrency（MUST）

### 5.1 Lifecycle states

| state | 意味 |
| --- | --- |
| ZERO | OBJECT_INIT sentinel（`magic==0 && lifecycle==0`; padding 非全検査） |
| INITING | reset/init 進行中（re-entry 拒否） |
| READY | init 成功; chip は STDBY_RC 期待 |
| FAILED | 失敗後; unsafe 操作拒否; retry は shutdown または失敗ドメイン規則に従う |
| SHUTDOWN | 明示 shutdown 後; re-init 可 |

### 5.2 Init / re-init 契約

| 事前 | 結果 |
| --- | --- |
| OBJECT_INIT ZERO | first init 試行可（caller MUST OBJECT_INIT） |
| SHUTDOWN | re-init 可（新 domain） |
| READY / INITING / FAILED | re-init **拒否**（INVALID_STATE）; 既存状態を壊さない |
| ACTIVE 中の concurrent init | single-owner 契約外 / re-entry → BUSY または INVALID_STATE |

First init precondition: **`NINLIL_SX1262_OBJECT_INIT` sentinel**（`magic==0 && lifecycle==0`）。未初期化 garbage を読んで判定する保証は **ない**（C UB）。

### 5.3 Single owner

- 成功 init 後、object lifetime まで **sole owner**。
- 内部 multi-thread lock を持たない。複数 thread からの同時 call は **undefined**（契約外）。
- 同一 owner の **re-entry**（init 中に init / command、READY 中の nested call via bus callback）は fail-closed（BUSY）、追加 SPI 0。

### 5.4 Shutdown

- idempotent when already SHUTDOWN。
- READY/FAILED → SHUTDOWN: ops/ctx clear、stats 保持方針は header 正本（last_error は保持可）。
- shutdown は RF TX を行わない。可能なら bus 無しで local state のみ。

---

## 6. Init sequence（exact; MUST）

成功時のみ READY。途中失敗は **rollback**（§7）後 FAILED、または config 段階なら ZERO のまま。

```text
I0  validate config+ops — bus 0
I1  INITING; in_flight=1
I2  reset_assert → delay_us(reset_pulse_us **== 1000**) → reset_deassert
    （失敗時も deassert 試行; 以降 SPI 禁止で FAILED）
I3  wait BUSY low
I4  GetStatus [0xC0,0x00] 2B — mode STBY_RC; cmd 3/4/5 fail; raw 保持
I5  GetDeviceErrors 4B **Clear より前** — raw 保持
      XTAL: errors!=0 → DEVICE_ERROR
      TCXO cold expected mask E = XOSC_START_ERR|IMG_CALIB_ERR (§9.2.1):
        (errors & ~E) != 0 → DEVICE_ERROR（他 bit 混在は fail）
        (errors & E) != 0 → expected_cold 記録（XOSC only / IMG only / both すべて可）
        errors == 0 → clear スキップ可
I6  if expected_cold: ClearDeviceErrors 3B
I7  SetRegulatorMode(LDO|DCDC)
I8  optional DIO2
I9  if TCXO:
      SetDio3AsTcxoCtrl → verify GetStatus
      Calibrate(ALL=0x7F) → verify GetStatus
      GetStatus + GetDeviceErrors → verify GetStatus → **errors must be 0**
I10 SetStandby(STDBY_RC) → **verify GetStatus** → **final GetStatus** STBY_RC only
    （verify + final の **2 回** GetStatus; 実装と一致）
I11 if ANT_SW_PRESENT: ant_sw_set(ctx, inactive=0) 安全初期 level
I12 READY
```

**MUST:** allowlist = GetStatus / GetDeviceErrors / ClearDeviceErrors / SetRegulatorMode / Calibrate / SetDio2 / SetDio3 / SetStandby。
**MUST:** 成功終端 **STBY_RC のみ**（旧「RC または XOSC」矛盾は **廃止**）。
**MUST NOT:** Clear→Get で初回 error を隠す。
**MUST NOT:** SetTx/SetRx/CW/CAD/FS/WriteBuffer 等 RF emission path。

### 6.1 SPI framing（control; exact lengths）

| コマンド | バイト列 / 長さ |
| --- | --- |
| GetStatus | `[0xC0, 0x00]` **2 bytes** full-duplex; status = byte1 |
| GetDeviceErrors | cmd 2 + data 2 = **4 bytes** total |
| ClearDeviceErrors | **3 bytes** write |
| SetRegulatorMode | 2 bytes |
| Calibrate | 2 bytes（mask `0x7F` = CAL_ALL） |
| SetDio3 | 5 bytes（voltage + delay24） |

SPI 物理: **Mode 0**（CPOL=0 CPHA=0）、**MSB first**、**clock ≤ 16 MHz**（board/port config）。
NSS Low→bytes→High は **1 atomic transaction**（途中 NSS 上げ禁止）。

### 6.2 BUSY 契約（MUST; 600ns + stuck clock + overflow-safe）

```text
pre:  wait_busy_low(timeout_ms)
xfer: atomic SPI (full-duplex; §6.3)
post: delay_us(post_spi_busy_guard_us ≥ 1)   // DS TSW max 600ns
      wait_busy_low(timeout_ms)
```

`wait_busy_low`（CPU 速度非依存）:

```text
interval_us = board.busy_poll_interval_us   // 必須; 1..1_000_000
timeout_us  = timeout_ms * 1000             // overflow → config reject
// MUST: interval_us <= timeout_us（各 busy/spi/tcxo timeout; overflow-safe）
// e.g. timeout_ms=1, interval_us=1_000_000 → reject
max_polls   = ceil(timeout_us / interval_us) + busy_poll_slack  // uint64; slack 1..16
loop:
  sample BUSY; if low → OK
  delay_us(interval_us)                     // tight spin 禁止
  now = now_ms
  // pure: ninlil_sx1262_busy_deadline_reached(start, now, timeout_ms)
  // elapsed = now - start (uint wrap-safe)
  // elapsed < timeout_ms  → 継続
  // elapsed >= timeout_ms → BUSY_TIMEOUT  (**exact == も timeout**; OK ではない)
  polls++ ≥ max_polls → BUSY_TIMEOUT        // clock 停止でも終了
```

| elapsed vs timeout | 結果 |
| --- | --- |
| `< timeout_ms` | 継続（BUSY が low なら OK） |
| `== timeout_ms` | **BUSY_TIMEOUT** |
| `> timeout_ms` | **BUSY_TIMEOUT** |

**MUST:** 正常単調 clock（各 interval あたり now が前進）では **deadline が cap より先または同時**に発火し得るよう slack は小さく、cap が deadline 前に常時発火する設計にしない。
**MUST:** frozen clock では poll cap で終了。
**MUST NOT:** `timeout_ms*100+64` の spin-only cap。
**MUST NOT:** exact elapsed==timeout を成功扱いする（false-green）。

### 6.3 Write / GetErrors status + BUSY-before-decode（MUST）

一次資料（**DS Rev2.2 Table 10-1** Data-to-host: **byte0 = RFU**, **bytes[1:n] = Status**；**Table 13-85** GetDeviceErrors: **rx[0]=RFU, rx[1]=Status**, data `rx[2..3]`）に従い、status は **常に `rx[1]`** を decode する。`rx[0]` を status と扱うことは **禁止**。

**BUSY 完了同期が先（MUST）:** SPI transport **成功**後は、status が 3/4/5/1/6 であっても
`post_spi_busy_guard` → **post-BUSY low** を **完了してから** `rx[1]` を decode / FAILED 化する。
（旧: status decode が guard/BUSY より先に return → BUSY 同期欠落）

| 段階 | 規則 |
| --- | --- |
| 全 SPI xfer | full-duplex; allowlist + **closed frame schema**（exact len/params） |
| SPI **transport fail** | post-BUSY **しない**（command 未開始の可能性）; portable 層に pending 無し; port は own SM |
| SPI **成功** | **必ず** post_guard + post-BUSY → その後 `rx[1]` decode |
| 各 xfer の **rx[0]** | **RFU** — status として decode **しない** |
| 各 xfer の **rx[1]**（post-reset 後） | mid-init accepted **`{0,2}` のみ**（**RFU=1** / fail 3/4/5 / **TX_DONE=6** → STATUS_INVALID） |
| write 完了後 | 追加 GetStatus で当該 write 結果を再検査 |
| GetDeviceErrors | data `rx[2..3]`; `rx[1]` 捨てない |
| 初回 reset 直後 GetStatus のみ | previous 不定 → mode STBY_RC; cmd は **3/4/5 fail only**（accepted 非強制） |

**Host spy:** `miso_rfu_byte` / `status_byte` 独立。(a) bad RFU + good status → OK。(b) good RFU + bad status → fail **after** guard/BUSY 観測。

### 6.4 ESP SPI finite wait / pending ownership（MUST; BUSY と別責務）

一次資料: ESP-IDF v5.5.3 `spi_master` — `get_trans_result` timeout 時も descriptor は driver 所有のまま（DMA temp は result 受領時のみ解放）。`remove_device` は queue 残存で `ESP_ERR_INVALID_STATE`。

| 項目 | 契約 |
| --- | --- |
| 禁止 | `spi_device_polling_transmit`（内部 `portMAX_DELAY`） |
| 必須 | `spi_device_queue_trans` + `spi_device_get_trans_result` に **finite ticks**（`spi_timeout_ms`→ticks、0 禁止） |
| NSS | 1 transaction atomic（queue_size=1） |
| get_result **OK** | `pending_trans` clear; 通常継続 |
| get_result **timeout** | **`pending_trans` を保持**; SPI **poison**（新規 xfer 禁止）; pure SM → `TIMEOUT_HELD` |
| `spi_drain_max_attempts` | **0 → default 3**; else **closed 1..16**（config reject outside） |
| drain | `bus_drain`: finite `get_trans_result` 再試行。総待ち **≤ attempts × spi_timeout_ms**（overflow-safe 証明） |
| late completion | pending clear（poison 維持）→ clean shutdown → re-init 可 |
| drain 予算尽 | `REBOOT_REQUIRED`: **remove_device/free しない**; **re-init 禁止** |
| **SHUTDOWN_REBOOT_REQUIRED 時 caller MUST** | bus object **本体**と **trans_storage / tx_scratch / rx_scratch** を **device reboot 完了まで生存・immutable（不変）**に保つ。free / memset / re-init / 再利用 **禁止**（late DMA が buffer に触れ得る → UAF 禁止） |
| shutdown 戻り | `SHUTDOWN_OK` / `SHUTDOWN_REBOOT_REQUIRED` / `SHUTDOWN_FAIL`; remove/free の **戻り値を検査** |
| 検査 | pure pending SM: budget 0/1..16/17; finite wait; reboot object-storage ban; host single-file C11 -Werror compile of pending_logic |

**MUST NOT:** timeout 直後に `pending_trans=NULL` して `remove_device`/`free` する。
**MUST NOT:** REBOOT_REQUIRED 中に bus object を free/reuse する。

### 6.5 ESP GPIO / host validation（MUST; safe init order）

```text
1. gpio_config OUTPUT (RESET [, ANT_SW])
2. drive safe levels: RESET=high, ANT=inactive (polarity from ant_sw_active_high)
3. gpio_config INPUT (BUSY, DIO1)
4. SPI bus init …
```

- output 役割: `GPIO_IS_VALID_OUTPUT_GPIO`; input: `GPIO_IS_VALID_GPIO`
- **`ant_sw_active_high` 必須明示**（1=active-high / 0=active-low）; active-high 固定禁止
- 後段（input/SPI）失敗時も **safe level を維持**して cleanup（UAF/中途半端な RF path 禁止）
- pin 重複 / `spi_host` 妥当性; `gpio_set_level` 失敗は **無視禁止**

### 6.6 ESP delay_us / NRESET（MUST; 0-tick 禁止）

- `us < threshold`（実装 default 5000）: `esp_rom_delay_us`（busy wait; NRESET 100µs/1ms を正確に満たす）
- それ以上: **overflow-safe** `ceil(us * tick_rate / 1e6)` で ticks 化し **最低 1 tick**（`pdMS_TO_TICKS(1)==0` になり得る丸め下げを禁止）
- `us + 999` の単純 ms 丸め + `pdMS_TO_TICKS` のみに依存しない

### 6.7 ESP bus object lifecycle（MUST）

```text
ninlil_esp_idf_sx1262_bus_t bus = NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT; // {0}
```

- **caller MUST** `NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT`（全 zero）で宣言 — **未初期化 storage を読むことは C UB** であり、garbage を「検出できる」とは主張しない
- first init 受理: `magic==0 && lifecycle==ZERO`（**OBJECT_INIT sentinel 契約**; padding 全検査ではない）
- re-init 受理: `magic==MAGIC && lifecycle==SHUTDOWN` のみ
- それ以外 → fail-closed（ACTIVE / REBOOT_REQUIRED / 不正 sentinel）
- init 成功後 `magic=MAGIC`, lifecycle=ACTIVE

---

## 7. Failure / rollback / retry（MUST）

| 失敗点 | 副作用 | 終了 state |
| --- | --- | --- |
| I0 validate | bus 0 | 変更なし（ZERO のまま） |
| I2–I3 reset/BUSY | 可能なら reset line を deassert 試行; 追加 SPI 0 | FAILED |
| I4–I11 SPI/status | 追加 RF opcode 0; 可能なら SetStandby 試行は **しない**（部分 init で二次コマンドを増やさない） | FAILED |
| re-entry | 追加 SPI 0 | 既存 state 維持 + BUSY status |

**Retry:** FAILED からの直接 init は INVALID_STATE。`shutdown` → semantic domain 再初期化後にのみ再試行可（SHUTDOWN re-init）。
**Post-fail:** TX deny は引き続き deny; SetTx 0。

---

## 8. TX path（R4 deny; MUST）

### 8.1 Explicit deny API

```text
ninlil_sx1262_request_transmit(...) → TX_DENIED
```

- 任意 lifecycle（NULL 以外）で **SPI 0**（特に opcode `0x83` を送らない）。
- frame pointer を dereference して device buffer に書かない。
- stats `tx_deny` を saturating increment（rh が有効なとき）。

### 8.2 Structural absence

production `drivers/sx126x/**` および production port backend において:

| 禁止 | 検査 |
| --- | --- |
| SetTx を送る call path | source gate + host mutation |
| `RadioLib` include/symbol | source gate |
| alternate symbols (`ninlil_sx1262_tx`, `ninlil_sx1262_send`, …) | source gate |
| H1 を迂回する raw TX API | source gate |

Banlist 定数としての `0x83` **リテラル定義は許可**（拒否判定用）。**送信 path は禁止**。

---

## 9. Status / reason / stats（closed）

Header 正本。最低限:

| status | 意味 |
| --- | --- |
| OK | 成功 |
| INVALID_ARGUMENT | null / bad config |
| INVALID_STATE | wrong lifecycle / re-init |
| BUSY | re-entry |
| BUSY_TIMEOUT | BUSY pin stuck |
| SPI_ERROR | bus transfer fail |
| SPI_TIMEOUT | SPI 後 BUSY timeout |
| DEVICE_ERROR | GetDeviceErrors non-zero（非 expected） / post-cal residual |
| STATUS_INVALID | mode/cmd_status invalid（**SKU 識別ではない**; 旧 CHIP_MISMATCH を改名） |
| TX_DENIED | R4 TX 要求拒否 |
| UNSUPPORTED | reserved |

stats（saturating u64）: init_attempts / init_ok / init_fail / spi_xfers / spi_errors / busy_timeouts / tx_deny / reentrant / config_reject。

---

## 10. Bus ops 契約（MUST）

```text
reset_assert(ctx) -> 0 OK / non-zero fail
reset_deassert(ctx)
busy_is_high(ctx, &out_high)  out_high 1=high/busy
spi_transfer(ctx, tx, rx, len)  full-duplex; rx may be NULL for write-only
delay_us(ctx, us)
now_ms(ctx, &out_ms)          monotonic domain
ant_sw_set(ctx, active)       optional
```

- 失敗は non-zero。D1 は成功を捏造しない。
- **Allowlist enforcement（実態一致）:**
  - **D1** が SPI 前に allowlist + closed frame schema を強制（送らないことが正）
  - **ESP adapter** も RF-banned / non-allowlisted を **defense-in-depth で拒否**（docs 旧「adapter は拒否しない」は廃止）
  - **host spy** は観測用に任意 opcode を受け得る（production ではない）
- Host spy scriptable fault: reset / BUSY read / delay（reset・guard・poll）/ now 位置指定 / SPI each step / short / freeze・monotonic deadline / wrong status + **event trace ordering**

---

## 11. ESP-IDF production-private bus adapter（candidate）

- 置き場: `ports/esp-idf/include/ninlil_esp_idf/sx1262_bus.h` + `ports/esp-idf/src/esp_idf_sx1262_bus.c`
- pin は **caller config**（Seeed 既定を Core に埋め込まない）。example は docs Informative または port example に分離可。
- SPI: Mode 0、MSB first、clock は config。
- **ISR 禁止**（task context; fail-closed）— M3-basic と同型。
- R4 では RF TX / continuous RX を実装しない。
- host pure は adapter をリンクしない（spy で代替）。

---

## 12. Testing（exact; MUST）

### 12.1 Host unit（`sx1262_r4` CTest）

少なくとも（**追跡 ID = テスト関数名**。gate が欠落検出）:

| ID | MUST | テスト関数 / 観測 |
| --- | --- | --- |
| T01 | success init order（reset→BUSY→allowlist SPI→STBY_RC） | `test_success_xtal` — `k_xtal_ok` + STBY_RC + SetTx0 |
| T02 | null object / config / ops / out_backend | `test_null_args` |
| T03 | 各必須 pin UNSET | `test_each_required_pin_unset` |
| T04 | pin duplicate | `test_pin_duplicate` |
| T05 | 全 feature mismatch | `test_feature_mismatches` |
| T06 | reserved0 / interval≤timeout / reset≠1000 | `test_config_bounds` |
| T07a | SPI fault **全** XTAL/TCXO expected steps + RF opcode0 | `test_bus_faults_matrix` |
| T07b | ops 各 function pointer NULL matrix | `test_bus_faults_matrix`（ops copy） |
| T07c | BUSY read fail 位置（reset 後 / post-SPI） | `test_fail_busy_read_positions` |
| T07d | delay fail: reset / guard / poll interval | `test_delay_fail_positions` |
| T07e | now fail: first + loop | `test_now_fail_positions` |
| T08a | frozen clock poll cap | `test_frozen_clock_poll_cap` |
| T08b | clock wrap | `test_clock_wrap` |
| T08c | poll formula exact | `test_timeout_boundary_exact` |
| T08d | pure deadline helper before/exact/after | `test_busy_deadline_helper` |
| T08e | monotonic wait: before=OK; exact/after=BUSY_TIMEOUT（wait_start 観測） | `test_monotonic_deadline_boundary` |
| T09 | re-entry during INITING | `test_initing_reentry` |
| T10 | READY 二重 init 拒否 | `test_shutdown_reinit` |
| T11 | FAILED→shutdown→reinit | `test_failed_shutdown_reinit` |
| T12 | TX deny 全 lifecycle | `test_tx_deny_all_lifecycles` |
| T13 | allowlist/schema/ban + **independent opcode pin** | `test_cmd_frame_schema` + `test_primary_opcode_pin` + gate |
| T14 | object size/align | `test_object_size_align` |
| T15 | SPI pending + drain 1..16 + REBOOT object lifetime | `test_spi_pending_ownership_sm` |
| T16 | mid-status {0,2}; **event trace** SPI→GUARD→BUSY→fail | `test_mid_status_closed_set_after_busy` |
| T17 | MISO rx[1] / RFU independent | `test_miso_status_byte_position` |
| T18 | TCXO cold mask matrix | `test_tcxo_cold_*` |
| T19 | ESP GPIO safe-init SM + polarity | `test_esp_gpio_safe_init_sm` |

### 12.2 Independent expectations

- spy が記録する **expected opcode sequence vector** は test 側 **Semtech primary literal constants**（`SX126X_GOLDEN_*` / hex）で独立 pin。
- **MUST NOT:** expected 生成に production `NINLIL_SX1262_CMD_*` を使う（macro 誤変更の false-green 禁止）。
- production macros は `test_primary_opcode_pin` で golden literal と **別途比較**（drift 検出）。
- golden sequence は本章 §3.1 / §6 と一致。

### 12.3 Structural gate（`sx1262_r4_gate`）

- production sources: banlist TX opcodes の **送信**不在、RadioLib 不在、spy 不在
- cmake authority registration
- public ABI clean
- **§12.2 independent opcode pin:** test `SX126X_GOLDEN_*` と production `NINLIL_SX1262_CMD_*` を **同一 Semtech hex literal** でそれぞれ pin（allowlist 8 + SetTx ban + CAL_ALL）
- `k_xtal_ok` / `k_tcxo_dio2_xosc` / `test_cmd_frame_schema` が production `NINLIL_SX1262_CMD_*` を期待値生成に使っていないこと
- mutation self-test（drop allowlist check、inject SetTx send、drop cmake、leak spy into production list、inject RadioLib include、**flip golden 0xC0、flip production 0xC0、reinject production macro into golden vector、drop `test_primary_opcode_pin`、schema production macro**）

### 12.4 tests-OFF hygiene

`NINLIL_BUILD_TESTS=OFF` の private archive / source list に:

- `sx1262_bus_spy`
- `tests/support/*sx1262*`
- oracle/fixture symbols

が **混入しない**（nm / source authority gate）。

### 12.5 Sanitizers / packaging

- focused ASan+UBSan on host R4 tests when sanitizer lane available
- ESP-IDF component packaging: portable D1 sources を authority 経由で登録可; **compile ≠ HIL**

---

## 13. Acceptance / evidence boundary

| 証拠 | 言えること | 言えないこと |
| --- | --- | --- |
| host CTest + gate green | control-plane state machine / deny / allowlist | RF 放射 0 の物理証明 |
| esp32s3 compile | image builds | radio works |
| datasheet PDF citation complete | timing の一次根拠 | legal |
| R10 HIL | SKU 測定 | 全国認証 |

### 13.1 Required HIL / open blockers（R4 complete 主張禁止）

1. **BLOCKER-HIL-SPI:** ESP32-S3 + 実 SX1262 で reset/init/GetStatus/STDBY_RC の実機確認（DS 引用 ≠ 実測）。
2. **BLOCKER-BOARD-TIMING:** board profile の `reset_pulse_us` / BUSY / TCXO delay の **実測妥当性**（DS typical/公式 1ms example の選択根拠）。
3. **BLOCKER-HIL-RF:** RF TX/RX は R9+R10。R4 では実施も完成主張もしない。
4. **BLOCKER-R1-EDGE:** H1 edge への D1 配線と R9 sole-edge は未。
5. **BLOCKER-R2:** permit authority 未実装。

**DS 一次資料ピンは完了**（§3.0）。「web 不可で未確証」は **廃止**。

---

## 14. Informative: example board pins（NOT portable defaults）

Seeed XIAO ESP32-S3 + Wio-SX1262 系で **よく使われる**例（**Core に embed しない**; 検証は board owner の責任）:

| 役割 | 例 GPIO |
| --- | --- |
| SCK | 7 |
| MISO | 8 |
| MOSI | 9 |
| NSS | 41 |
| RESET | 42 |
| DIO1 | 39 |
| BUSY | 40 |
| ANT_SW | 38 |

本表は Informative。欠落・基板差を portable 既定で隠してはならない。

---

## 15. 文書メンテナンス

- docs/23 §10.2 R4 行を本 candidate 状態へ更新
- docs/09 / docs/07 / docs/README / README / CHANGELOG / ADR index を同期
- R4 complete と書かない
