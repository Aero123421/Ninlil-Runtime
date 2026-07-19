# Ninlil Architecture Decision Records

Accepted ADRは、Ninlil自体の長期的な設計判断を記録します。新しい判断を追加し、過去ADRを直接書き換えず、置き換える場合は新ADRから`Supersedes`を明記します。

- [ADR-0001: Project Boundary and First Release](0001-project-boundary-and-first-release.md)
- [ADR-0002: EventFact Conflict Projection Precedence](0002-eventfact-conflict-projection-precedence.md)
- [ADR-0003: Radio / USB Boundary Dependency Direction](0003-radio-usb-dependency-direction.md)（Accepted）
- [ADR-0004: R2 Durable Physical Compliance Permit Authority](0004-r2-durable-permit-authority.md)（Accepted; [24章](../24-r2-physical-compliance-permit-authority.md)）
- [ADR-0005: U5 CellOperatingAssignment and Control Protocol v2](0005-u5-cell-operating-assignment-control-v2.md)（Accepted）
- [ADR-0006: U6 Transport Custody on Control Path](0006-u6-transport-custody.md)（Accepted）
- [ADR-0007: R3 LoRa Airtime Calculator](0007-r3-airtime-calculator.md)（Accepted; [27章](../27-r3-airtime-calculator.md); host candidate — R3 complete / Japan / HIL 非主張）
- [ADR-0008: R4 SX1262 Control-Plane Backend](0008-r4-sx1262-control-plane-backend.md)（Accepted; [28章](../28-r4-sx1262-control-plane-backend.md); host candidate — RF TX / HIL / legal 非主張）
- [ADR-0009: R5 LAB_ONLY Profile Loader and Full Permit Bind Matrix](0009-r5-lab-only-profile-loader.md)（Accepted; [29章](../29-r5-lab-only-profile-loader.md); host candidate — R5 complete / FIELD / Japan / HIL 非主張）
- [ADR-0010: R6 Secure Compact Radio Wire Normative Freeze](0010-r6-secure-radio-wire.md)（**Accepted**; [30章](../30-r6-secure-radio-wire.md); NRW1 one-way / DATA·ACK lanes / E2E security id / LINK_ACK TX·RX split / route terminal / tombstone reserve — Stage 9 docs freeze; independent re-GO 2026-07-19 P0=P1=P2=0; R7 full AEAD / M4·M5 / ESP N6 capacity / RF·USB 実機 HIL / legal / production 未完）
- [ADR-0011: R7 Private Crypto Provider Boundary](0011-r7-crypto-provider-boundary.md)（**Accepted**; [31章](../31-r7-crypto-provider-and-aead.md); R6 N6 hash pin不変、portable validation wrapper + Host OpenSSL exact 3.x + ESP-IDF v5.5.3 mbedTLS; push/PR/ESP-IDF CI全成功、independent POST-CI P0=P1=P2=0 GO。**AcceptedはT0候補のみ。R7 full / 実機KAT / RF・USB HIL / legal 未完**）

KGuard固有の採用・移行判断は`productv1/docs/99-decision-log.md`へ記録します。
