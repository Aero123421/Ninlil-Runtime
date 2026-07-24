# V1 LAB RC 残件限定文書

- 作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`
- 計画: `docs/work/2026-07-23-ninlil-v1-lab-plan.md`
- 統合 gate 前提: commit `c5298d9`（項目 10b 前半）
- 日付: 2026-07-24
- 目的: V1 LAB RC 後に **残る作業を物理実機系のみ** に限定する証拠

## V1 LAB で完了したもの（コード + host 検証）

| 縦切り | 証拠 |
| --- | --- |
| 1–10a 全項目 | `docs/work/2026-07-23-v1-a1a-evidence.md` … `v1-a10a-evidence.md` |
| 統合 E2E gate | `docs/work/2026-07-23-v1-integration-gate-evidence.md` |
| 10b packaging/examples/docs | `docs/work/2026-07-23-v1-a10b-evidence.md` |

host 上で `public submit → … → source outcome` の単一 topology と 9 故障注入が
green（`v1_integration_gate_e2e`, structural check）。stub/TODO 0（各 evidence 参照）。

## RC 後に残る作業（**物理実機系のみ**）

以下は V1 LAB RC の **スコープ外** とし、V1 完成定義から除外する。

| ID | 残件 | 根拠（未完了の事実） |
| --- | --- | --- |
| P1 | **ESP flash / USB 実機 HIL** | 項目 9 evidence: 「実 USB HAL」「実 RF HIL は host sim のみ」（`v1-a9-evidence.md` §残件） |
| P2 | **SX1262 physical RF TX/RX HIL** | 同上; R4/R5/R6/R7 各 docs が `compile ≠ HIL` |
| P3 | **power-cut / FULL durable attestation（ESP）** | 項目 1 / ESP matrix: FULL success 禁止、`COMMIT_UNKNOWN`（`v1-esp-provider-matrix.md`, `v1-a1c-evidence.md`） |
| P4 | **Display node 実機 E2E** | master plan §0: physical `LAB` lane は M3/M5 subset 後; V1 examples は host loopback のみ（`examples/v1_lab/display_latest_state.c`） |
| P5 | **Leak node 実機 E2E** | 同上（`examples/v1_lab/leak_measurement.c`） |
| P6 | **U1–U3 Required HIL（USB CDC 実経路）** | [docs/23](../23-usb-radio-boundary.md): Required HIL pending |
| P7 | **production 法規認定（C6 本経路）** | 計画 §2 V2; 10a evidence 非主張 |

### 明示的に V1 RC に含めないもの（V2）

計画 `docs/work/2026-07-23-ninlil-v1-lab-plan.md` §2 より:

- D3-S4..S12 scanner 網羅、relay、multi-parent、完全 wire fragmentation
- production 法規認定、全 crash 境界・形式証明
- **SBOM / release signing**（10b packaging 非主張）
- A2-b oracle 200-vector 拡充（freeze 済み）

## V1 LAB RC tag 前チェックリスト

| チェック | 状態 |
| --- | --- |
| 統合 gate green | `c5298d9` + evidence |
| packaging（LICENSE/NOTICE/third-party/manifest/smoke） | 10b evidence |
| examples 4 本ビルド・実行 | 10b evidence |
| stub/TODO 0（10b 新規経路） | 10b evidence |
| public ABI 変更なし | diff 確認 |

## 参照

- V2 roadmap: `docs/work/2026-07-23-ninlil-v1-lab-plan.md` §2
- 配布物: `docs/v1-lab-distribution-manifest.md`
- 利用者向け: `docs/v1-lab-quickstart.md`

RC=0
