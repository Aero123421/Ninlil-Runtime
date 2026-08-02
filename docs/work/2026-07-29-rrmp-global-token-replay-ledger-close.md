# RRMP global durable token replay ledger close

日付: 2026-07-29

対象: ADR-0020 private implementation candidate。formal `SPEC_ACCEPTED`、
`RELEASE_SUPPORTED`、physical RF / power-cut HILは主張しない。

## Closed defect

旧実装はNPT1を「1 scope = current token 1件」として再構築していた。このため同じscopeの
次handoffで過去tombstoneが消え、別scopeへ同じtoken digestを転用できた。

修正後のNPT1はparent namespace全体のglobal durable replay ledgerである。

- `TOKEN_LIVE`と`TOMBSTONE_USED`を合計256件保持する。
- current NPA1は自身のtoken entryをexact 1件参照する。
- 過去のunmatched `TOMBSTONE_USED`を次handoffでも保持する。
- 同一scope・別scope・cold restart後のdigest再利用は`TOKEN_REPLAY`。
- 256件保持中の未使用257件目は`RESOURCE`。duplicate判定を先に行う。
- FIFO/LRU/time-based implicit evictionは行わない。
- NPT1 48-byte slot、4096-byte page、8 physical pageのwire/storage layoutは変更しない。
- owner workspaceにshadow ledgerを追加せず、durable NPT1を直接authorityにする。

## Evidence

専用test `ninlil_rrmp_token_ledger_test`は、同じscopeでS1–S6を256回完走し、
NPT1 page occupied countがexact `84 + 84 + 84 + 4`、全entryが
`TOMBSTONE_USED`であることを検査する。その後:

1. 最初のtokenを同じscopeで再利用 → `TOKEN_REPLAY`
2. 最初のtokenを別scopeで再利用 → `TOKEN_REPLAY`
3. 未使用257件目 → `RESOURCE`
4. namespace export/import後に1–3を再実行 → 同じ結果

実行済み:

```text
normal:
  ninlil_rrmp_codec_test PASS
  ninlil_rrmp_sm_test PASS
  ninlil_rrmp_crash_corrupt_test PASS
  ninlil_rrmp_token_ledger_test PASS

ASan + UBSan:
  ninlil_rrmp_codec_test PASS
  ninlil_rrmp_sm_test PASS
  ninlil_rrmp_crash_corrupt_test PASS
  ninlil_rrmp_token_ledger_test PASS

spec authority:
  vector generator check/self-test PASS
  independent Python gate check/self-test PASS
  independent Node gate check/self-test PASS
```

## Residual

明示GC APIはprivate v1に存在しない。ADR-0020のS6完了・retention証明を満たす将来の
normative GC契約が追加されるまでは、256件到達後の新規handoffをfail-closedで拒否する。
real NOR/NVS power-cutとphysical multi-parent RFはHIL `NOT_RUN`のまま。
