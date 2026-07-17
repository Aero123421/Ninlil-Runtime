# ADR-0006: U6 Transport Custody on Control Path

状態: **Accepted**<br>
決定日: 2026-07-17

## Context

[04章](../04-runtime-api-and-storage.md) は Transport Custody の概念順序を既に持つ:

1. receiver が payload + metadata を durable commit
2. receiver が `TRANSPORT_CUSTODY_ACCEPTED` 相当を返す
3. sender が transfer evidence を durable commit
4. `custody_release_policy` が許すときだけ sender が payload を削除

一方 USB path（[23章](../23-usb-radio-boundary.md)）は raw CDC / NCG1 / NCL1 成功を **non-custody** と明示している。U6 は control plane 上で custody transfer を **exact wire + state + storage atomicity** として閉じる必要がある。

誤った固定の仕方:

1. `write()` / NCG1 decode / ACK enqueue を custody 成功とみなす。
2. Transport Custody と Application Receipt（`RECEIVED` / `DURABLY_RECORDED` / `APPLIED`）を同一 stage にする。
3. ESP storage が `FULL` を `COMMIT_UNKNOWN` しか返せない現状（[21章](../21-m3-esp-idf-durable-storage.md)）で custody success を名乗る。
4. fragmentation / resume を未設計のまま部分 frame を spool 成功と扱う。
5. custody catalog を control protocol v1 closed set へ silent 追加する。

## Decision

### 1. 正本は [26章](../26-u6-transport-custody.md)

States、transitions、wire、resource limits、COMMIT_UNKNOWN recovery、vector set、ESP promotion gate は **26章が唯一の Normative 正本**である。

### 2. Control protocol v2 上の private custody catalog

- custody message は [ADR-0005](0005-u5-cell-operating-assignment-control-v2.md) の **`selected_control_version == 2`** でのみ合法（`≥ 2` / future v3 silent 禁止）。
- NCL1 envelope v1 を維持する。v1 closed catalog へ type を追加しない。
- U5 assignment と U6 custody は同一 control_version domain を共有するが、**semantic owner は別**（assignment ≠ custody）。

### 3. 成功条件の厳密分離（MUST）

| 観測 | custody 成功か |
| --- | --- |
| raw CDC / C1 write accept | **否** |
| NCG1 encode/decode OK | **否** |
| NCL1 decode OK / logical ACK enqueue | **否** |
| receiver **FULL** storage commit of atomic custody group → `STORAGE_OK` | **receiver local accept の必要条件** |
| `CUSTODY_ACCEPT` wire 送信 accept | **peer 通知であり、sender 側 evidence ではない** |
| sender **FULL** commit of transfer evidence → `STORAGE_OK` | **sender local custody-complete の必要条件** |
| Application Receipt stage 上昇 | **否**（別 domain） |

### 4. Dual FULL commit + release policy + responsibility end

04章順序を wire 化:

1. OFFER（payload bind: transfer_id + attempt + digest + length）
2. receiver FULL atomic group
3. ACCEPT
4. sender FULL evidence
5. release policy 適用（sender）

Receiver の **custody 責任終了**は upper **handoff FULL** または explicit **discard FULL** のみ。TTL による payload GC は禁止（[26章 §7.6](../26-u6-transport-custody.md)）。

`COMMIT_UNKNOWN` は両端で **両 truth（committed / not）を仮定して fail-closed recovery** する。silent success 禁止。Boot recovery は [26章 §12](../26-u6-transport-custody.md) の exact algorithm。

### 5. Single-frame 上限・fragmentation 非主張

- U6 v1 は **単一 NCL1 message に収まる payload のみ**。
- fragmentation / multi-frame resume / streaming は **主張しない・実装しない**。
- 上限超過は OFFER 前に local reject（wire に partial を載せない）。

### 6. ESP FULL / custody success promotion

- host pure model media および POSIX SQLite 等 **FULL を契約どおり証明できる port** では host 実装・crash injection を許可する。
- ESP-IDF storage 現状（21章）: `commit(FULL)` は unattested で **`COMMIT_UNKNOWN`** → **R_HELD 成功遷移禁止、`CUSTODY_ACCEPT` 禁止**、OFFER 応答は **`CUSTODY_REJECT_STORAGE` に統一**（BUSY 逃げ禁止）。
- recovery / **read-back 一致後も** unproven 中は ACCEPT を送らない（UNKNOWN を success に昇格禁止）。higher attempt の readback は **full bind**（transfer_id+attempt_id+digest+length）比較。
- durable: `NCT1`/`NCP1`/`NCS1`/`NCH1`/`NCD1`/`NCT0`、handoff は NCH1+NCT1 handoff_complete **同一 FULL**、clock は platform **id128 clock_epoch_id bit-exact**（u64 切詰め禁止）。
- **単一 namespace `ninlil.ctl.v1`**。sender spool FULL 必須。terminal tombstone/GC は責任終了後のみ。
- OFFER に `sender_deadline_mono_ms` **無し**（reserved）。
- 独立再レビューまで GO 禁止。

### 7. Symmetric bidirectional model

Controller→Cell と Cell→Controller で **同一 state machine / 同一 wire** を用いる。初期 profile は single-frame。role は transfer ごと（RuntimeRole と独立）。

## Rationale

- non-custody 規則を壊すと restart / power-cut で ownership 二重化・消失が隠れる。
- Application Receipt と混ぜると endpoint apply 前に「届いた」表示が固定される。
- ESP 未証明 FULL を success にすると 21章の fail-closed 契約と矛盾する。
- single-frame に閉じることで U6 を実装可能な有限状態に保ち、M2 BoundedTransfer と責務分離できる。

## Consequences

- 実装 slice **U6** は 26章 + 本 ADR に従う。U5 と独立 PR 可能だが control_version v2 と U4 session を共有する。
- docs/23 の U6 行は 26章へ委譲する。
- U6 complete ≠ Application Receipt complete ≠ M3 exit ≠ USB series complete。
- public ABI への custody API 露出は別 ADR。

## Related

- [26-u6-transport-custody.md](../26-u6-transport-custody.md)
- [25-u5-cell-operating-assignment.md](../25-u5-cell-operating-assignment.md)
- [04-runtime-api-and-storage.md](../04-runtime-api-and-storage.md)
- [21-m3-esp-idf-durable-storage.md](../21-m3-esp-idf-durable-storage.md)
- [23-usb-radio-boundary.md](../23-usb-radio-boundary.md)
- [ADR-0003](0003-radio-usb-dependency-direction.md)
- [ADR-0005](0005-u5-cell-operating-assignment-control-v2.md)
