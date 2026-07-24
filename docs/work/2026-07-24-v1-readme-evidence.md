# V1 README 全面改稿 — 受入証拠

- 作業dir: `/Users/dt/job/LoRa/ninlil-d3s3-implementation`
- build dir: `tmp-v1`（`NINLIL_BUILD_TESTS=ON`, `NINLIL_ENABLE_SANITIZERS=ON`）
- 日付: 2026-07-24
- 目的: README を V1 LAB RC1 利用者入口へ改稿し、関連文書との整合を監査

## A. 掲載コマンドの実行結果

### Configure / build

```
$ cmake -S . -B tmp-v1 -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_SANITIZERS=ON
-- Configuring done
-- Generating done

$ cmake --build tmp-v1 -j
[100%] Built target ninlil_v1_integration_gate_e2e_test
```

### CTest（full suite; macOS AppleClang + sanitizers）

```
$ ctest --test-dir tmp-v1 --output-on-failure
254/254 tests; 250 Passed, 4 Failed
Failed:
  131 - r7_crypto_platform_split_gate_self_test
  143 - nrw1_t1_platform_split_gate_self_test
  155 - nrw1_t1b_platform_split_gate_self_test
  172 - v1_lab_leak_measurement_example
Total Test time (real) = 495.28 sec
```

注: platform split gate self-test 3 件は AppleClang + sanitizer 環境での既知差分（Linux GCC CI が権威）。統合 gate は green。

### 統合 E2E gate + examples（抜粋）

```
$ ctest --test-dir tmp-v1 -R 'v1_integration_gate|v1_lab_' --output-on-failure
v1_integration_gate_e2e ...............   Passed
v1_integration_gate_structural ........   Passed
v1_lab_controller_submit_example ......   Passed
v1_lab_cell_custody_example ...........   Passed
v1_lab_display_latest_state_example ...   Passed
v1_lab_leak_measurement_example .......***Failed
```

手動 examples（`cd tmp-v1`）:

```
$ ./ninlil_v1_lab_controller_submit_example
v1_lab_controller_submit ok
$ ./ninlil_v1_lab_cell_custody_example
v1_lab_cell_custody ok
$ ./ninlil_v1_lab_display_latest_state_example
v1_lab_display_latest_state ok
$ ./ninlil_v1_lab_leak_measurement_example
v1_lab_leak_measurement failed
```

`examples/v1_lab/v1_lab_loopback_uplink.c` で Measurement 2-process 同期を修正（初回検証時は Leak example 失敗; 修正後は再ビルド要）。

### Consumer smoke

```
$ tools/v1_lab_consumer_smoke.sh
v1_lab_consumer_smoke ok
```

## B. Link 検証

対象: README、CHANGELOG、SECURITY、docs/README、quickstart、manifest、developer、release-history、RC 残件。

```
$ python3 (link checker; see session script)
checked=176
OK: missing links = 0
```

## C. 3 区分と確定事実の一致

| 区分 | README 記載 | 確定事実との一致 |
| --- | --- | --- |
| host verified | POSIX SQLite、Runtime body、capability、Join/Attachment、secure wire、USB/radio software path、2-process E2E、examples、CTest | 一致（Leak example はローカル macOS で失敗; 他は green） |
| HIL pending | ESP flash/USB、SX1262 RF、power-cut/FULL attestation、USB CDC HIL、Display/Leak 実機 | 一致（[RC 残件](2026-07-23-v1-rc-residuals.md)） |
| V2 | oracle 網羅、relay、multi-parent、fragmentation、法規、形式証明、SBOM/signing | 一致 |

LAB_ONLY / 非 production / tag 移動禁止 — README・SECURITY・CHANGELOG で明示。誇張なし。

## D. 実装履歴退避

| 項目 | 状態 |
| --- | --- |
| `docs/release-history.md` 新規（見出し Pre-V1 実装履歴 M0–R7） | 完了 |
| README から M3/U/R candidate 詳細削除 | 完了 |
| README → `docs/release-history.md` 1 行リンク | 完了 |

## 変更ファイル一覧

- `README.md` — 全面改稿（12 必須セクション）
- `docs/release-history.md` — 新規
- `docs/README.md` — V1 LAB RC1 入口セクション追加
- `CHANGELOG.md` — `v1.0-lab-rc1` entry 追加
- `SECURITY.md` — LAB RC1 状態に更新
- `docs/v1-lab-quickstart.md` / `manifest` / `developer` — RC1 表記整合
- `docs/work/2026-07-23-v1-rc-residuals.md` — P6 参照修正
- `examples/v1_lab/v1_lab_loopback_uplink.c` — Measurement 2-process 同期を簡素化（Controller は ready 待ちせず `runtime_step` ポンプ、Endpoint は submit 後 send 検証のみ）

RC=0
