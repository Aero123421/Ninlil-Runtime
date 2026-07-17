# ADR-0009: R5 LAB_ONLY Profile Loader and Full Permit Bind Matrix

状態: Accepted<br>
決定日: 2026-07-17<br>
対象: R5 host candidate only（FIELD / PRODUCTION / HIL / legal 完成を主張しない）

## Context

[23章 §9.3](../23-usb-radio-boundary.md) と [05章](../05-security-and-compliance.md) は Physical Compliance Permit の **全 bind 項目**（Hardware/Regulatory identity+revision、SiteAssignment identity/revision/epoch、controller_term、assignment_digest、permit_bind_generation、transmitter、channel、PHY、frame digest/length、conservative max airtime、not-before/expiry、permit sequence）を発行時・consume 時に exact bind する。

R1 は live L_core の一部を H1 で再検証する。R2 は durable one-shot / FIFO / ceiling を提供する。R3 は closed SX1262 LoRa ToA を提供する。しかし:

1. **LAB_ONLY 以外を fail-closed する HardwareProfile / RegulatoryProfile loader が無い。**
2. U5 の **controller_term / assignment_digest / permit_bind_generation** は R1 snapshot / R2 issued 232B layout に **含まれない**（R2 meta の `assignment_generation` は generation の durable 片翼のみ）。
3. R2 durable layout（schema 1 / meta 200B / issued 232B）を破壊せずに全項目を閉じる必要がある。

## Decision

1. **R5 は production-private 合成層**（`src/radio/profile_loader.{h,c}`）とする。public `include/ninlil` 非露出。
2. **LAB_ONLY のみ** active にできる。`CANDIDATE` / `DEPLOYMENT_APPROVED` / `REVOKED` / unknown は load または activate で fail-closed。Japan production 数値・法的認証は **捏造しない**（合成 LAB 値のみ）。
3. **全 §9.3 bind 項目**は R5 が **発行時・consume 時**に exact 比較する。R2 durable に無い term/digest は R5 RAM registry（outstanding ≤8、seq keyed）で保持する。
4. **R2 durable schema 1 を変更しない。** `assignment_generation`（meta off 156）は R5 `permit_bind_generation` と **exact durable sync via ninlil_pcp_commit_live_binding (full L_core+gen FULL txn)**（`ninlil_pcp_set_assignment_generation` / get; bind/fence/issue で一致検査）。publish 時 generation≥1; assignment fence で R2 `revoke_all` + R5 registry clear + generation++ + durable set。
5. **R1 sole transmit-with-permit を迂回しない。** R5 は `ninlil_radio_hal_permit_ops` 互換 validate/consume を提供し、内部で R5 full-bind 検査の後に R2 `ninlil_pcp_validate` / `ninlil_pcp_consume` を呼ぶ。
6. **R3** が算出した `airtime_us` を per-permit `max_airtime_us` 候補とし、RegulatoryProfile ceiling と比較。OVERFLOW / ceiling 超過は issue 拒否。
7. Profile 変更: active outstanding がある in-place 変更禁止; revision rollback は REVOKED/未知へ fail-closed; truncation/corruption/duplicate/未知 approval は fail-closed。
8. **非主張:** R5 complete / FIELD / PRODUCTION / Japan legal / RF / HIL / R4/R7/R9 / U5 wire apply / secure radio wire。

## Consequences

- 実装・host tests・semantic gate は [29章](../29-r5-lab-only-profile-loader.md) に従う。
- R1/R2/R3 既存 CTest と durable layout / CRC golden を壊してはならない。
- restart 後: R2 recover は durable L_core を復元するが、R5 RAM registry は空。outstanding が残る場合 R5 は **consume を full-bind 欠落で拒否**し、owner は `fence_and_bump_generation`（R2 revoke_all + registry clear）してから再 bind する。

## Related

[ADR-0003](0003-radio-usb-dependency-direction.md) · [ADR-0004](0004-r2-durable-permit-authority.md) · [ADR-0007](0007-r3-airtime-calculator.md) · [05](../05-security-and-compliance.md) · [23 §9 / §10.2](../23-usb-radio-boundary.md) · [24](../24-r2-physical-compliance-permit-authority.md) · [25](../25-u5-cell-operating-assignment.md) · [27](../27-r3-airtime-calculator.md) · [29](../29-r5-lab-only-profile-loader.md)
