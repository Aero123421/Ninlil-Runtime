# Pre-V1 実装履歴（M0–R7 candidates）

本ページは README から退避した、V1 LAB RC1 **以前** の slice 別 implementation candidate 履歴です。現行のリリース状態は [README](../README.md) と [V1 LAB RC 残件](work/2026-07-23-v1-rc-residuals.md) を正とします。

## Foundation / Domain Store（M0–D3）

- `include/ninlil/*.h` の public ABI 宣言と C11 / C++17 consumer compile smoke
- enum、`sizeof`、`offsetof`、reason registry、Operator projection、hook mirror、仕様 vector、requirements traceability の機械検査
- scheduler candidate、deadline projection、Required Receipt、resource ledger/batch、Submission preflight/admission の pure C11 model
- Runtime config / Platform 検証、11 種 capacity 導出、Storage / Bearer / Clock / entropy 分類、Stage 9 health gate の pure C11 Lifecycle model
- Runtime Store v1 の 17 bootstrap key、typed big-endian record、CRC32C、境界 / 破損検査を行う portable C11 codec
- Stage1 success だけが発行する header/pointer-free accepted-config projection から canonical binding/identity、17-record presence/integrity、profile/identity decision、compact lazy bootstrap plan を作る Runtime Store L2a2 pure model
- Lifecycle / Runtime Store Core を public `ninlil` と TEST fixture から分離した非 export `ninlil_runtime_private` STATIC target
- Domain Store v1 の family 5/6 catalog、D1-A〜D1-B3o body codec、D2 bounded scanner（S1–S6）、D3-S0..S3 implementation（S4..S12 pending）
- atomic FULL admission write-set と commit 結果別 ownership/recovery projection
- in-memory Storage conformance fixture、simulated Bearer / Tx Gate、Origin Authorization fixture
- **POSIX SQLite storage port（host production 候補）** — opaque namespace BLOB、WAL + `synchronous=FULL`、host conformance test。**Runtime body 統合前の候補として記録**

## M3（ESP-IDF packaging / control framing / storage candidate）

- **M3-prep + M3-basic:** portable Core/private library を ESP-IDF component として package し、pinned ESP-IDF `v5.5.3` で ESP32-S3 smoke を target build。port-owned clock / entropy / execution adapters（[18章](18-m3-prep-esp-idf-component.md)、[20章](20-m3-basic-esp-idf-platform-adapters.md)）。**M3 complete / hardware verified ではない**
- **M3-slice control framing:** Controller↔Cell Agent 向け private `NCG1` bounded byte-stream frame codec（[19章](19-m3-control-byte-stream-framing.md)）
- **M3-slice owner-task / Cell Agent skeleton / loopback TxPermit**（[22章](22-m3-owner-cell-agent-skeleton.md)）
- **M3-slice durable storage candidate:** format 4 dual-slot durable-storage 候補（[21章](21-m3-esp-idf-durable-storage.md)）。host conformance 済みだが ESP FULL は `COMMIT_UNKNOWN`、実機 power-cut HIL 未実施

## U0–U7（USB / control transport）

- **U0 USB / physical radio boundary freeze（docs）** — [ADR-0003](adr/0003-radio-usb-dependency-direction.md)、[23章](23-usb-radio-boundary.md)
- **U1 implementation candidate / host tests** — portable C1 byte-stream + A1 POSIX USB/serial adapter。Required HIL Linux+macOS physical USB CDC pending
- **U2 A2 ESP CDC implementation candidate** — `esp_tinyusb==2.1.1` locks。Required HIL flash+host CDC roundtrip pending
- **U3 C3 control-session + C4 pump implementation candidate** — NCG1 を C1 へ接続。HELLO session state machine は U4+
- **U4 NCL1 pure codec + logical session host candidate** — exact 26-byte header、47 wire vectors
- **U5 / U6 Normative docs freeze** — assignment / transport custody（実装は V1 LAB 以前は pending）

## R1–R7（radio / secure wire / crypto）

- **R1 ninlil_radio_hal host candidate** — sole `transmit_with_permit` + host spy
- **R2 Physical Compliance Permit authority host candidate** — durable permit authority（FIFO / expiry / consume durability）
- **R3 LoRa airtime host candidate** — closed SX1262 LoRa integer ceil-us calculator
- **R4 SX1262 control-plane host candidate** — reset/init/SPI + TX deny（[28章](28-r4-sx1262-control-plane-backend.md)）
- **R5 LAB_ONLY profile loader host/ESP packaging candidate**（[29章](29-r5-lab-only-profile-loader.md)）
- **R6 NRW1 compact context-handle wire docs freeze Accepted** — `wire_profile_id=0x11`（[30章](30-r6-secure-radio-wire.md) / [ADR-0010](adr/0010-r6-secure-radio-wire.md)）。independent **re-GO 2026-07-19 P0=P1=P2=0**。**R6 docs freeze Accepted ≠ R7 full AEAD codec / M4·M5 / ESP N6 capacity / RF·USB 実機 HIL / Japan legal / production radio complete**。public ABI 非変更。**compile ≠ HIL**。
- **R6 Chunk D private N6 host candidate** — durable record codec、HMAC/HKDF-SHA-256、bounded context store。**R7 full AEAD wire codec、M4/M5 binder、ESP N6容量成立、RF/USB実機HIL、production radioは未実装・未検証。compile ≠ HIL。**
- **R7 T0 private crypto provider Accepted** — Host OpenSSL 3.x、ESP-IDF mbedTLS（[31章](31-r7-crypto-provider-and-aead.md)）。independent POST-CI GO **re-GO 2026-07-19 P0=P1=P2=0**。**AcceptedはT0 private crypto provider候補のみ。R7 full wire codec・counter/storage・FRAG/LINK/CELL/HA・実機KAT・RF/USB HIL・Japan legal・production radioは未完。compile/link ≠ HIL。**
- **R7 T1 NRW1 SINGLE wire codec Accepted**（[32章](32-r7-t1-nrw1-single-wire-codec.md) / [ADR-0012](adr/0012-r7-t1-nrw1-single-wire-codec.md)）。independent POST-CI GO **re-GO 2026-07-19 P0=P1=P2=0**。**AcceptedはT1 private pure SINGLE codec候補のみ。30章 §18 full artifact/state・counter/storage/replay・FRAG/LINK/CELL/HA・W1/L1・実機KAT・RF/USB HIL・Japan legal・production radio・R7 fullは未完。compile/link ≠ HIL。**
- **R7 T1b context binding / verified HKDF Accepted**（[33章](33-r7-t1b-context-binding-hkdf.md) / [ADR-0013](adr/0013-r7-t1b-context-binding-hkdf.md)）。independent POST-CI GO **re-GO 2026-07-19 P0=P1=P2=0**。**AcceptedはT1b private stateless候補のみ。context install・counter/nonce/AEAD/replay・T1 composite・W1/L1/N6/M4/M5・LINK/FRAG/CELL/HA・実機KAT・RF/USB HIL・Japan legal・production radio・R7 fullは未完。compile/link ≠ HIL。**
- **R7 T1c Authenticated Hop Fresh-Install Owner Proposed docs-only**（[34章](34-r7-t1c-authenticated-hop-fresh-install-owner.md)）。**implementation / vectors / CTest / Accepted 未。** R7 full・RF/USB HIL・Japan legal・production radioは非claim。compile/link ≠ HIL。

## Pre-V1 で未統合だった主要ギャップ（V1 LAB RC1 で解消）

V1 LAB RC1 以前の README が列挙していた blocker（public Runtime body 未接続、end-to-end Reliable Command / Durable Event 未統合、production storage 未接続など）は、V1 LAB 縦切り 10 項目の host simulation 完成により **host verified 区分で解消** されています。物理実機系（HIL pending）と V2 スコープは [RC 残件](work/2026-07-23-v1-rc-residuals.md) を参照してください。
