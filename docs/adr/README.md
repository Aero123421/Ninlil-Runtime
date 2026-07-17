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

KGuard固有の採用・移行判断は`productv1/docs/99-decision-log.md`へ記録します。
