# SX1262 radio_hil ESP compile/link evidence (2026-07-29)

状態: **Informative compile/link evidence** — not RF HIL PASS, not ADR-0025 Accepted,
not Japan legal / TELEC certification.

## Claim layers (do not collapse)

| Layer | Meaning | Status in this doc |
| --- | --- | --- |
| **compile_link_radio_hil** | ELF/map/nm/stack gates green | Proved by `sx1262_radio_hil_elf_evidence_gate` |
| **same_session_pcp_recover** | `PCP_RECOVER_SAME_SESSION` on live `g_pcp` | Linked; **not** a restart claim |
| **physical_two_boot_recovery** | `PREPARE_TWO_BOOT` → `REBOOT` → `COMPLETE_TWO_BOOT` | Protocol executable; **NOT_RUN** without device |
| **physical_powercut_pass** | Full power-cut + reconstruct | **NOT_RUN** (always until fixture) |
| **physical_stack_watermark** | FreeRTOS high-water mark on device | **NOT_RUN** (static .su call-chain only) |
| **rf_hil_pass / japan_legal** | Field RF / TELEC | **false** |

Deprecated alias `restart_recovery_protocol` is always **false**. Same-session recover must never set it.

## Image authority

| Role | Platform | Digest | Launcher |
| --- | --- | --- | --- |
| **CI / release authority** | linux/amd64 | `sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb` | `tools/esp_idf_ci_docker_run.sh` |
| Local Apple Silicon only | linux/arm64 | `sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1` | `tools/esp_idf_local_arm64_radio_hil_run.sh` |

ESP-IDF pin: **v5.5.3**. arm64 digest is **not** CI authority.

## Board profile (P0)

Immutable profile id: `xiao_esp32s3_wio_sx1262_v1`

### Primary source identity (informative — not physical PASS)

| Field | Value |
| --- | --- |
| Document | Seeed Studio **Wio-SX1262** datasheet |
| Version | **v1.0** |
| Use in this tree | Justifies release encode choices only (compile/link + host bus-spy). **Does not** claim RF HIL PASS, spectrum measurement, Japan legal, or on-bench module verification. |

Datasheet facts recorded into the release profile:

| Datasheet statement (v1.0) | Release encode |
| --- | --- |
| Module supply **3.3 V typical** | `vdd_op_mv = 3300` |
| TCXO **powered by SX1262 DIO3**; TCXO voltage **≥ 200 mV below VCC** | `TCXO_PRESENT` + DIO3 @ **3.0 V** (`0x06`); margin 3300−3000 = 300 mV |
| **DIO2 internally connected** to the module RF switch | `DIO2_RF_SWITCH` + `SetDio2AsRfSwitchCtrl enable=1` |
| Host-side **RF_SW** receive control on this carrier | `ANT_SW_PRESENT` on GPIO 38 (active-high), distinct from internal DIO2 path |

### Encode table

| Setting | Value |
| --- | --- |
| Pins | NSS=41 SCK=7 MOSI=9 MISO=8 RST=42 BUSY=40 DIO1=39 ANT_SW=38 (active-high) |
| Features | `TCXO_PRESENT` + `DIO2_RF_SWITCH` + `ANT_SW_PRESENT` |
| TCXO | DIO3 @ **3.0 V** (`0x06`), delay **5000** RTC steps, VDD 3300 mV |
| RF switch | `SetDio2AsRfSwitchCtrl enable=1` (module-internal DIO2→RF switch) |
| External RF_SW | GPIO ANT_SW (carrier receive path; not a substitute for DIO2) |
| Calibration | `CAL_ALL` (`0x7F`) after SetDIO3 |
| Regulator | DCDC |

Release radio_hil binds only this profile; Kconfig pin mismatch → compile `#error`.  
Host bus-spy tests prove exact opcode order and voltage encoding; ANT_SW-only is a negative profile (no Dio2/Dio3/CAL).

## Sole path

```
immutable XIAO+Wio board profile (DIO2 / DIO3@3V / CAL_ALL)
  → approved LAB profile docs
  → R5 load/activate + site assignment
  → PCP flash FULL + recover/publish + clock/entropy
  → R5 issue → HAL transmit_with_permit
  → sx1262_r9_edge → phy_arm_tx (CAD/LBT + SetTx)
```

## Recovery honesty (P1)

| Command | Claim |
| --- | --- |
| `PCP_RECOVER_SAME_SESSION` (legacy alias `RECOVER_PCP`) | same-session only; `claim=same_session_not_restart` |
| `PREPARE_TWO_BOOT` | RTC receipt + fence; class=old |
| `REBOOT` | `esp_restart` (not power-cut) |
| `COMPLETE_TWO_BOOT <prev_boot_id>` | fresh authority reconstruct; class=old/new/fenced; rejects unchanged boot_id |

Executable without device:

```sh
python3 tools/sx1262_radio_hil_protocol.py self-test
python3 tools/sx1262_radio_hil_protocol.py not-run-evidence
# with device:
python3 tools/sx1262_radio_hil_protocol.py run --port <dev>
python3 tools/sx1262_radio_hil_protocol.py two-boot-run --port <dev>
```

## Stack budget (Sol xhigh re-audit)

Method: **max of retained main-task call-chains + ≥4 KiB margin**  
(not max-single-frame, not INIT-only).

### Worst chain: TX / new-epoch (fresh `.su`)

| Frame | Bytes |
| --- | ---: |
| `app_main` | 336 |
| `handle_line` | 352 |
| `cmd_tx_data` | 1168 |
| `ninlil_r5_issue` | 288 |
| `ninlil_r5_issue_with_bind` | 1088 |
| `ninlil_pcp_issue` | 5152 |
| `pcp_algorithm_e_body` | 9152 |
| `pcp_rw_scan_check` | 48 |
| `pcp_scan_namespace` | 672 |
| **TX chain sum** | **18256** |
| Explicit margin | **4096** |
| **Required** | **22352** |
| `CONFIG_ESP_MAIN_TASK_STACK_SIZE` | **24576** (24 KiB) |

Also gated (must appear in `.su` + ELF nm/map): INIT (12048), recovery_same_session, RX.  
Gate fails closed on the **max** chain sum.

False-green rejected:
- max-single-frame only (9152 ≪ 16 KiB)
- INIT-only at 16 KiB (fits INIT, fails TX)

Physical FreeRTOS watermark: **NOT_RUN** (separated).

Gate: `python3 tools/sx1262_radio_hil_elf_evidence_gate.py self-test` and `check --su-dir …`.

## Artifacts / gates

```sh
bash tools/esp_idf_local_arm64_radio_hil_run.sh v5.5.3
python3 tools/sx1262_radio_hil_elf_evidence_gate.py check \
  --elf ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.elf \
  --map ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.map \
  --sdkconfig ports/esp-idf/radio_hil_app/sdkconfig \
  --nm-dump ports/esp-idf/radio_hil_app/build/ninlil_radio_hil.nm.txt \
  --out-json ports/esp-idf/radio_hil_app/build/ninlil_radio_hil_evidence.json
```

### Final-ELF required symbols

- HAL/R9/R2/R5 authority symbols (unchanged)
- Flash: `ninlil_port_esp_storage_flash_bind`, `config_production`, `ninlil_pcp_recover`
- Board profile: `ninlil_sx1262_board_profile_xiao_wio_sx1262_v1`, `_copy_…`

### Forbidden

- Session ledger init/shutdown
- Mock permit mint
- Legacy `request_transmit_with_permit`

### Map needles

`ninlil_sx1262_board_profiles`, `ninlil_sx1262_backend`, plus authority path needles.

## Physical NOT_RUN remaining

1. **physical_two_boot_recovery** — needs connected board + `two-boot-run`
2. **physical_powercut_pass** — needs power-cut fixture (not software reboot)
3. **rf_hil_pass / OTA peer / spectrum** — not claimed
4. **japan_legal / TELEC / ADR-0025 Accepted** — not claimed
