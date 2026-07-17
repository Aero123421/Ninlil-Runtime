# ADR-0007: R3 LoRa Airtime Calculator (host candidate)

状態: **Accepted**<br>
決定日: 2026-07-17<br>
対象: R3 only（R4/R5/RF/legal/HIL/Japan production profile 非主張）

## Context

R2 は per-permit `max_airtime_us` と meta ceiling を分離する。owner が渡す ToA は **短く見積もってはならない**。
本 ADR は **main 未リリースの最初の R3 freeze** を記録する。

## Decision

1. **formula_version = 1**（初版。将来の破壊変更でのみ上げる）。
2. Algebra pin: sx126x_driver **v2.3.2** commit `9636dc4660ada4eeddf91eb7b3f7f241000bf202` の numerator/BW。
3. Datasheet pin: **DS.SX1261-2.W.APP Rev 2.2** §6.1.4 p41 / §6.1.1.4 p40 / §13.4.5 p90 / §13.4.5.2 p92 / §6.1.1.1 p38。
4. AUTO LDRO: `2^SF·100000 ≥ BW·1638`（Ts ≥ 16.38 ms）。
5. **SF5/6:** LDRO OFF→effective 0、ON→effective 1 で受理。代数は DE を使わない。AUTO は §4 判定（closed BW では通常 0）。
6. ToA 正本: **uint64** U と ceil-us/ms。uint32 driver ms wrapper は oracle 禁止。
7. CR ∈ {1..4} のみ; 5..7 は INVALID。
8. SF5/6 推奨 preamble 12 は R5 policy; R3 math は ≥6。
9. `airtime_us` が u32 を超える場合は **OVERFLOW fail-closed**（切捨て禁止）。
10. private C11 + independent oracle + gate; nonclaims は [27章](../27-r3-airtime-calculator.md)。

## Consequences

実装・vectors・gate は 27章 §acceptance に従う。R3 complete / Japan / HIL / re-review GO を名乗らない。

## Related

[27章](../27-r3-airtime-calculator.md) · [ADR-0004](0004-r2-durable-permit-authority.md) · [23章](../23-usb-radio-boundary.md)
