# ADR-0008: R4 SX1262 Control-Plane Backend (reset / init / SPI only)

状態: Accepted<br>
決定日: 2026-07-17<br>
番号: **ADR-0008**（Normative 正本 **docs/28**。docs/25–26 / ADR-0005–0006 は U5/U6 予約、docs/27 / ADR-0007 は R3 予約 — 衝突禁止）

## Context

R1 は `ninlil_radio_hal` の sole `transmit_with_permit` 契約と host spy を host candidate として置いた。R2 Physical Compliance Permit authority は [24章](../24-r2-physical-compliance-permit-authority.md) / [ADR-0004](0004-r2-durable-permit-authority.md) の private host candidate であり、legal / production profile / RF / HIL は未完である。**R4** は [23章 §10.2](../23-usb-radio-boundary.md) の **SX1262 backend reset/init/SPI only** である。

次を同時に誤ると危険である:

1. portable Core に ESP-IDF / FreeRTOS / SPI master 型を漏らす。
2. Seeed / XIAO 等の board pin を portable 層へ hardcode する。
3. SetTx / SetRx / continuous-wave 等の RF emission path を R4 で実装・完成主張する。
4. R1 sole edge や R2 authority 完成を R4 で偽装する。
5. tests-only spy / oracle を tests-OFF production private archive に混入する。
6. Semtech 一次資料無しに timing / status 数値を推測固定する。

## Decision

1. **D1 placement:** production-private SX1262 control-plane backend は `drivers/sx126x/`（[ADR-0003](0003-radio-usb-dependency-direction.md) D1）。public `include/ninlil` に昇格しない。
2. **Portable vs port:** bus は抽象 ops（GPIO reset/BUSY、SPI transfer、monotonic delay/now）のみ。ESP-IDF / FreeRTOS / `spi_device_*` 型は `ports/esp-idf/` production-private bus adapter に閉じる。
3. **Board wiring:** NSS / SCK / MOSI / MISO / RESET / BUSY / DIO1 / ANT_SW と optional TCXO / DIO2 RF-switch を board config で明示。未設定・重複・矛盾は **init 前 reject**。Seeed pin を portable 既定にしない。
4. **R4 scope:** hard reset、BUSY 待ち、allowlisted SPI control commands、safe **STDBY_RC** 終了、lifecycle / single-owner / timeout / rollback / re-init のみ。**physical RF TX/RX は実装しない。**
5. **TX fail-closed:** 任意の TX 要求 API は **explicit deny**、SPI 副作用 0（SetTx を送らない）。production sources に SetTx / alternate TX edge / RadioLib transmit を **構造的に置かない**（forbid list + gate）。
6. **Opcode allowlist:** GetStatus / Get|ClearDeviceErrors / SetRegulatorMode / Calibrate(ALL) / SetDio2 / SetDio3 / SetStandby。RF emission opcode は banlist。
7. **Primary sources:** DS.SX1261-2.W.APP **Rev 2.2 Dec 2024** + sx126x_driver **v2.3.2** + SWSD003 **v2.3.0** を docs/28 に pin。NRESET は R4 で **exact `reset_pulse_us=1000`（SWSD003 1ms）** — DS「typically 100µs」は **保証 minimum としない**。BUSY TSW 600ns→post guard、TCXO delay steps×15.625µs ≠ BUSY ms、GetErrors before Clear、最終 **STBY_RC only**、mid-init cmd_status **`{0,2}` only**、SPI で SX1261/2 SKU 識別禁止（STATUS_INVALID）。HIL/実測未は非主張。
8. **Concurrency:** single owner after successful init。内部 multi-thread lock 無し。re-entry / wrong-owner → fail-closed、unsafe SPI 0。
9. **Testability:** host pure deterministic bus spy + fault injection。spy / oracle / fixture は `tests/` のみ。tests-OFF ship archive に混入禁止。
10. **Nonclaims:** R4 complete / production radio / RF TX / legal / Japan profile / HIL PASS / R1 series complete / R2 authority complete / R9 sole-edge complete を名乗らない。public ABI 変更なし。

## Consequences

- 実装正本は [28章](../28-r4-sx1262-control-plane-backend.md)。
- CTest: host model tests + structural `sx1262_r4_gate`（mutation self-test 含む）。
- ESP-IDF component は portable backend source を authority list 経由で同梱し得るが、**compile ≠ HIL**、RF 動作は主張しない。
- R9 まで physical SPI TX path を sole-edge に閉じない。

## Related

[ADR-0003](0003-radio-usb-dependency-direction.md) · [23章 §9 / §10.2](../23-usb-radio-boundary.md) · [24章](../24-r2-physical-compliance-permit-authority.md) · [28章](../28-r4-sx1262-control-plane-backend.md) · [05](../05-security-and-compliance.md) · R1 `src/radio/radio_hal.h`
