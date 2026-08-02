# SX1262 two-board RF HIL runner

- Date: 2026-08-03
- Scope: existing `radio_hil_app` physical TX/RX path
- Physical result: `NOT_RUN`（USB serial device未接続）

## 変更

`tools/sx1262_radio_hil_protocol.py pair-run`を追加した。2台へ同じ
`radio_hil_app`を書き込み、USB serialを2本指定すると、既存の
R1/R2/R5/R9 sole RF pathで固定長payloadを両方向に送る。

成功条件は、指定件数の全messageについて受信payloadが送信payloadとbyte一致し、
送信側がIDLEへ戻ることである。JSON evidenceには方向、sequence、payload、RSSI、
SNR、radio generationを保存する。一部成功やtimeoutはPASSにしない。

```sh
python3 tools/sx1262_radio_hil_protocol.py pair-run \
  --port <first-dev> --peer-port <second-dev> \
  --count 20 --interval-ms 100 --payload-bytes 32
```

## Software verification

- Python compile: PASS
- protocol self-test: PASS
- SX1262 sole-edge source gate: PASS
- radio HIL ELF evidence self-test: PASS
- Markdown link gate / `git diff --check`: PASS

## 非主張

実機が接続されていないため、RF HIL自体は`NOT_RUN`である。runnerの成功も
Fabric/ApplicationData、Join、relay、field SLO、日本の法規適合、TELEC、
物理電源断を証明しない。
