# ADR-0005: U5 CellOperatingAssignment and Control Protocol v2

状態: **Accepted**<br>
決定日: 2026-07-17

## Context

U0–U4 は USB control の NCG1 framing、NCL1 envelope v1、HELLO/PING/PONG/RESET を private Normative として固定した（[23章](../23-usb-radio-boundary.md)、[ADR-0003](0003-radio-usb-dependency-direction.md)）。次に必要なのは、Cell Agent へ **cell / channel / operating role / SiteAssignment 識別** を渡す **CellOperatingAssignment** である。

誤った固定の仕方は次を招く:

1. NCL1 closed catalog v1（HELLO/PING/PONG/RESET のみ）へ assignment message を **黙って追加**し、v1 peer 互換と golden を破壊する。
2. `RuntimeRole`（CONTROLLER/CELL_AGENT/ENDPOINT）、USB **logical link role**（HELLO initiator/responder）、**mutable CellOperatingAssignment** を同一 enum に混ぜる。
3. USB Control HELLO 成功だけで **FIELD RF 認可**が成立したとみなし、Physical Compliance Permit / SiteAssignment を迂回する。
4. assignment を flash 永続 LKG として RF 許可に使い、session fence 後も stale assignment で TX する。
5. public `include/ninlil` や KGuard 語彙へ control catalog を早期昇格する。

## Decision

### 1. Control protocol v2 を exact freeze（NCL1 envelope v1 は維持）

| Domain | 決定 |
| --- | --- |
| NCL1 envelope | **logical_version exact 1** 維持。header layout / magic / MAX body は [23章 §7](../23-usb-radio-boundary.md) のまま |
| NCL1 closed catalog **v1** | HELLO / HELLO_ACK / CTRL_ERROR / PING / PONG / RESET **のみ**。**黙って type を追加しない** |
| Negotiated control protocol | HELLO の `min/max/selected_control_version` で **exact v2** を導入。v2 が assignment（および [U6](../26-u6-transport-custody.md) custody）catalog の必要条件 |
| Version 番号空間 | `logical_version` と `control_version` は **共有しない**（[06章](../06-versioning-and-compatibility.md)） |

`selected_control_version < 2` の session では v2 message_type を **reject**（v1 catalog の unknown と同じ fail-closed）。v2 を v1 peer へ silent 送出しない。

### 2. 三層 role 分離（MUST）

| 層 | 意味 | 寿命 | 所有者 |
| --- | --- | --- | --- |
| **RuntimeRole** | CONTROLLER / CELL_AGENT / ENDPOINT（[04章](../04-runtime-api-and-storage.md)） | Runtime create から destroy | Core create 引数 |
| **Logical link role** | USB control の HELLO initiator（Controller）/ responder（Cell）（[23章](../23-usb-radio-boundary.md)） | control session | C3 session |
| **CellOperatingAssignment** | cell_id / channel / operating_role / SiteAssignment identity·revision·epoch / controller term 等の **mutable 運用割当** | **当該 control session に bind**（volatile） | L1 / Cell local composition |

三者を同一 wire field や同一 public enum に畳まない。

### 3. 正本は [25章](../25-u5-cell-operating-assignment.md)

Byte layout、message catalog、precedence、ACK linearization、authority proof 境界、vector set、acceptance は **25章が唯一の Normative 正本**である。本 ADR は決定の要約である。

### 4. Authority proof 境界（USB HELLO ≠ FIELD RF）

- Control HELLO / session ACTIVE は **control channel liveness + framing session** のみ。
- **Physical RF TX** は [05章](../05-security-and-compliance.md) / [23章 §9](../23-usb-radio-boundary.md) の **Physical Compliance Permit** が sole edge。
- assignment の `authority_proof_kind` は **LAB_ONLY** 経路と **EXTERNAL_VERIFIED** 経路のみを U5 で閉じる。
- **FIELD_PILOT / PRODUCTION** environment で `AUTHORITY_NONE` または未検証 proof の assignment を **active SiteAssignment として Permit 発行に用いてはならない**。
- USB HELLO 成功・assignment ACK 成功だけでは FIELD RF 認可は成立しない。

### 5. Volatile session-bound assignment body + durable anti-replay watermark

- Active **assignment body** は `(session_generation, session_cookie)` に bind する。
- session INVALID / re-HELLO / link down → **即座に volatile active body を失効**。
- U5 は **durable last-known-good assignment body を RF 認可に使う契約を主張しない**。
- 一方、**durable anti-replay watermark（ARW）** を [25章 §7.6](../25-u5-cell-operating-assignment.md) で必須とする。ARW key は **`site_domain_id` domain**（assignment_identity を key に含めない）。value に last identity + **assignment_digest** + **authority_proof_digest** を FULL 永続し、identity 差し替えによる high-term 回避と equal-key 推測比較を禁止する。namespace は U6 と共有の `ninlil.ctl.v1`。
- ARW FULL 不能（ESP unproven 含む）では reconnect 耐性 apply / FIELD apply complete を主張しない。
- Wire: ASSIGNMENT_ACK body **exact 64**、REJECT **exact 76**（offset 一意; 旧 56/60 は非準拠）。
- v2 catalog 許可は **`selected_control_version == 2` のみ**（`>=2` / future v3 silent 禁止）。
- Physical Permit bind に **controller_term + assignment_digest + permit_bind_generation** を含め、higher apply は **L0–L9**（validate → permit fence FULL → ARW FULL → active → ACK）で唯一化する（[25章 §8.5](../25-u5-cell-operating-assignment.md)）。
- ESP unattested では ARW COMMIT_UNKNOWN **read-back 一致でも** active/ACK/FIELD 昇格禁止（U6 と同優先）。
- ARW key = recipient+site scope（36B）; value 172B + CRC; identity は value のみ。
- **R2 正本（現状）:** docs/24 + ADR-0004 は main 統合済みの Physical Compliance Permit Normative 正本。本 U5 branch は origin/main へ **rebase 済み**で、term/digest/`permit_bind_generation` fence は docs/24・05・23 と **docs 整合済み**。R2 runtime / HIL / legal / RF、U5 runtime 実装 complete は **未・非主張**。独立再レビューまで GO 禁止。

### 6. Private 実装境界

- U5 API / codec / state は production-private（U3/U4 と同様）。public ABI 昇格は別 ADR。
- handoff は **typed bounded copy-in / copy-out**。step/pump sole drive。`WOULD_BLOCK`。call を跨ぐ pointer 借用禁止。
- KGuard schema / policy / product message 名を必須語彙にしない。

## Rationale

- catalog 拡張を control_version 交渉に閉じることで、v1 golden と half-open recovery を壊さず assignment を追加できる。
- role 三層分離は Runtime 作成・USB session・現場運用割当の寿命差を実装が混同しないために必須である。
- FIELD RF を USB HELLO から切り離さないと Compliance Gate が形骸化する。
- 永続 LKG を今固定すると、membership epoch / controller fencing（M4）前に stale RF 許可が固まる。

## Consequences

- 実装 slice **U5** は 25章 + 本 ADR に従う。U4 complete を前提とし、U5 complete ≠ USB series complete ≠ M4/M5 complete。
- docs/23 の U5 行は 25章へ委譲する（最小同期）。
- control_version=2 交渉と v2 catalog は U6 custody message と同一 version domain を共有する（[ADR-0006](0006-u6-transport-custody.md)）。
- cryptographic suite の byte 固定は M4–M5 / EXTERNAL_VERIFIED provider の責務。U5 は proof **境界と kind catalog** を固定し、suite 中身を推測しない。

## Related

- [25-u5-cell-operating-assignment.md](../25-u5-cell-operating-assignment.md)
- [23-usb-radio-boundary.md](../23-usb-radio-boundary.md)
- [03-identity-and-join.md](../03-identity-and-join.md)
- [04-runtime-api-and-storage.md](../04-runtime-api-and-storage.md)
- [05-security-and-compliance.md](../05-security-and-compliance.md)
- [06-versioning-and-compatibility.md](../06-versioning-and-compatibility.md)
- [09-roadmap.md](../09-roadmap.md)
- [ADR-0003](0003-radio-usb-dependency-direction.md)
- [ADR-0006](0006-u6-transport-custody.md)
