# Ninlil V1 LAB RC1 完成記録

日時: 2026-07-24。tag: `v1.0-lab-rc1`（push 済み）。branch: codex/d3s3-implementation。

## 完成 = LAB 縦切り 10 項目(全て commit+push+Fable 独立検証)
| 項目 | 内容 | commit |
| --- | --- | --- |
| 1 | store/restart 正当性(durable allowlist/SQLite restart E2E/ESP no-success gate) | 79e3730/d6574a8/b545d80 |
| 2 | B1 runtime body(spine + delivery durable path) | d5c8aaa/6ede936 |
| 3 | B2-LAB provider 統合(POSIX 全 provider + restart cycle) | 9587b2e |
| 4 | B3 論理 capability(priority/deadline/retry + payload 上限) | 2db9478 |
| 5 | PC 間 1-hop E2E(2-process, ACK loss/dedup/timeout/restart) | 7bb2be6 |
| 6 | B5-LAB application capability(4 family + multi-target) | ce60bdf |
| 7 | C2-LAB Join/Attachment(M4 handshake + token mint) | 073772e |
| 8 | C3-LAB secure wire + context lifecycle(AEAD/replay/fresh-M4 restart) | fa0349e |
| 9 | C4/C5-LAB USB + radio software path | d806d3a |
| 10a | LAB_ONLY enforcement(sole-edge gate) | bed611c |
| 統合gate | 単一 topology 全経路 + 9 故障注入 | c5298d9 |
| 10b | packaging/examples/docs/RC 残件 | 6453060 |

## 基本品質(全て実証)
ACK/再送/重複排除/timeout/CRC・認証境界/再起動/false success 禁止/bounded・fail-closed
→ 統合 E2E gate の 10 シナリオで false success 0 / bounded termination / 範囲外 fail-closed。
examples 4 本(controller/cell/display/leak)build+run ok。full CTest(ASan/UBSan) green。

## RC 後残件 = 物理実機系 HIL のみ
docs/work/2026-07-23-v1-rc-residuals.md: ESP flash/USB、SX1262 RF、power-cut attestation、USB CDC HIL。

## V2 roadmap
巨大 oracle 網羅(A2-b B7/Sol r7、A2-c/d bridge、A3、A4)、relay、multi-parent、完全 wire fragmentation、production 法規認定、全 crash 境界/形式証明、D1 security audit、SBOM/signing。
A2-b oracle は commit 9f2ffe5(worktree fable/a2-d3s4-witness)で V1 凍結(185 vector closure)。
