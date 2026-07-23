# V1-LAB 送信可能 frame type exact-set manifest

- 状態: V1 item 10a 正本（C6-LAB enforcement）
- 規範: `docs/05` LAB_ONLY / `docs/30` R6 NRW1 / M4 Join primitive
- 非主張: 国内実運用可能・production 法規認定・RF/HIL（V2）

## スコープ

V1-LAB が **physical radio SPI TX に到達しうる** frame type の closed exact-set。
追加 type は manifest・gate・CTest を同時更新しない限り **送信不可**（fail-closed）。

**Retry** は独立 wire type ではない。同一 manifest type の再送であり、毎回 R5 bind → R2 permit → R1 consume → R9 SPI を通る。

## Exact-set（7 types）

| ID | Symbol | Owner | 用途 |
| --- | --- | --- | --- |
| 1 | `NINLIL_V1_FRAME_M4_JOIN_REQUEST` | M4/C2-LAB | Join handshake 開始（endpoint → controller） |
| 2 | `NINLIL_V1_FRAME_M4_JOIN_CHALLENGE` | M4/C2-LAB | Controller challenge（nonce/epoch） |
| 3 | `NINLIL_V1_FRAME_M4_JOIN_RESPONSE` | M4/C2-LAB | Endpoint identity proof 応答 |
| 4 | `NINLIL_V1_FRAME_M4_JOIN_INSTALL` | M4/C2-LAB | Install token 配布（成功時） |
| 5 | `NINLIL_V1_FRAME_M4_JOIN_REJECT` | M4/C2-LAB | Join 明示拒否 |
| 6 | `NINLIL_V1_FRAME_R7_HOP_DATA` | C3-LAB/R7 | 添付後 secure hop DATA lane（`wire_profile_id=0x11`） |
| 7 | `NINLIL_V1_FRAME_R7_HOP_ACK` | C3-LAB/R7 | 添付後 secure hop LINK_ACK lane |

コード正本: `src/radio/v1_frame_manifest.{h,c}`（`NINLIL_V1_FRAME_MANIFEST_COUNT == 7`）。

## V1 で送信不可（明示除外）

| 区分 | V1 扱い | 根拠 |
| --- | --- | --- |
| beacon / group | 除外（reserved reject） | `docs/30` `GROUP_AND_BEACON_RESERVED_REJECT` |
| diagnostics | 除外（reserved reject） | `docs/30` `DIAG_RESERVED_REJECT` |
| relay / forward | 除外 | V2 roadmap |
| wire fragmentation (START/CONT/FRAG_ACK) | 除外 | V2 roadmap |
| DEPLOYMENT_APPROVED / FIELD / PRODUCTION profile | 除外（LAB_ONLY のみ） | `docs/05` / R5 |

## Sole-edge 経路（Normative）

```
ninlil_c6_lab_transmit(frame_type)
  -> ninlil_v1_frame_type_is_transmittable (manifest)
  -> R5 ninlil_r5_issue (LAB_ONLY bind + R2 permit issue)
  -> R1 ninlil_radio_hal_transmit_with_permit
       digest -> R5 validate -> R5 consume (R2 authority)
  -> R9 ninlil_c6_lab_spi_tx_sim_edge (host SPI simulation)
```

bypass symbol `ninlil_c6_lab_spi_tx_bypass_direct` は test 専用。production success path からの call site = 0（`tools/c6_lab_enforcement_gate.py`）。

## LAB_ONLY 表示

V1-LAB は **国内実運用可能と表示しない**。production 認定・法規数値確定は V2（`docs/05` §Environment profile / `docs/09`）。
