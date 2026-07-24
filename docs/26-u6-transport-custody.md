# 26. U6: Transport Custody（control protocol v2）

状態: **Normative freeze（docs only; 実装未着手）**<br>
対象: Controller↔Cell Agent control path 上の **Transport Custody** transfer（durable spool ≠ raw CDC）<br>
依存: [ADR-0006](adr/0006-u6-transport-custody.md)（Accepted）、[ADR-0005](adr/0005-u5-cell-operating-assignment-control-v2.md)、[23章](23-usb-radio-boundary.md)、[04章](04-runtime-api-and-storage.md)、[21章](21-m3-esp-idf-durable-storage.md)<br>
関連: [01](01-architecture.md), [06](06-versioning-and-compatibility.md), [07](07-testing-and-quality.md), [09](09-roadmap.md), [12](12-foundation-abi.md), [14](14-foundation-ports-and-simulator.md), [19](19-m3-control-byte-stream-framing.md), [25](25-u5-cell-operating-assignment.md)

## 1. 位置付けと非主張

本章は USB series **U6** の **唯一の Normative 正本**である。Transport Custody の wire・状態・storage atomicity・recovery・resource limit・vector set を exact freeze する。

| 層 | 本章で固定するか | 状態 |
| --- | --- | --- |
| custody wire catalog（control_version == 2） | **する** | Normative private |
| dual FULL commit 順序 / release policy | **する** | Normative |
| COMMIT_UNKNOWN 両 truth recovery | **する** | Normative |
| Application Receipt との分離 | **する** | Normative |
| single-frame payload 上限 | **する** | Normative |
| fragmentation / multi-frame resume | **しない（非主張）** | 禁止 |
| ESP FULL production success | **現状禁止; HIL 後のみ昇格** | [21章](21-m3-esp-idf-durable-storage.md) |
| public C ABI | **しない** | 別 ADR |
| Application Receipt / Outcome complete | **しない** | 04/12/13 章 |
| U6 complete / USB series / M3 exit | **主張しない** | 実装+gate 後 |

**Forbidden claims:**

- raw CDC accept / NCG1 decode / NCL1 ACK enqueue = Transport Custody 成功
- `CUSTODY_ACCEPT` wire 単独 = Application `DURABLY_RECORDED` / `APPLIED`
- ESP unattested `commit(FULL)` 経路での custody success
- compile success = power-cut HIL PASS
- fragmentation / resume 対応済み
- control protocol v1 catalog への silent type 追加
- application payload の業務解釈が Core / custody に必須であること

## 2. 概念分離

### 2.1 Transport Custody とは

**Transport Custody** は、ある Runtime が **logical payload bytes の再送・保持責任**を peer Runtime へ移すことである（[04章](04-runtime-api-and-storage.md)）。

保証するもの:

1. receiver が custody group を **FULL durable** に所有した（`STORAGE_OK`）
2. sender が transfer evidence を **FULL durable** に記録した（`STORAGE_OK`）
3. release policy に従い sender が local payload を解放してよい

保証しないもの:

- application effect
- required Receipt stage
- terminal Outcome
- RF 配送
- peer process の生存（ACCEPT 後の peer crash は evidence と recovery で扱う）

### 2.2 Application Receipt との分離（MUST）

| 概念 | stage / 結果 | custody との関係 |
| --- | --- | --- |
| Transport Custody ACCEPT | custody state `R_HELD` / sender `S_RELEASE_OK` 候補 | **本 domain** |
| Receipt `RECEIVED` | adapter validation 後 | custody 成功を **自動昇格しない** |
| Receipt `DURABLY_RECORDED` | app durable | custody FULL と **同一 storage txn にしてもよいが別 record** |
| Receipt `APPLIED` / `VERIFIED` | application | custody 非関与 |
| Disposition / Outcome | 04/13 章 | custody 失敗を Outcome に写すのは **上位 policy**（本章は写像表を固定しない; silent 成功写像は禁止） |

### 2.3 Non-custody 観測（[23章 §6.2](23-usb-radio-boundary.md) 拡張）

| 観測 | custody 成功か |
| --- | --- |
| C1/raw CDC write accept | **否** |
| NCG1 encode/decode OK | **否** |
| NCL1 decode OK | **否** |
| `CUSTODY_ACCEPT` を TX intent に enqueue | **否**（receiver local FULL 前なら禁止; FULL 後でも sender 未 evidence） |
| `CUSTODY_ACCEPT` raw TX accept | **否**（peer 未達・sender 未 evidence） |
| receiver FULL `STORAGE_OK` only | **receiver accept 条件**（まだ transfer complete ではない） |
| sender evidence FULL `STORAGE_OK` | **sender custody-complete 条件** |
| Application Receipt | **否** |

## 3. Version / binding

1. NCL1 envelope v1 維持。v1 closed catalog 非拡張。
2. custody message は **`selected_control_version == 2`** の session のみ（[25章](25-u5-cell-operating-assignment.md) §2 と同一 domain）。
3. 全 custody message の NCG1 type は **`DATA` (0x03)** のみ。
4. U5 assignment と独立: custody に active assignment は **必須ではない**（USB control-only でも spool 可）。ただし `CAP_CUSTODY_ENDPOINT` を U5 が active にしている profile では、実装は capability を検査してよい（§10）。

## 4. Identifiers と binding

### 4.1 Stable fields

| Field | 型 | 規範 |
| --- | --- | --- |
| `custody_transfer_id` | 16-byte opaque | **transfer の安定 ID**。retry/reconnect で不変。sender が割当（CSPRNG または admission-issued）。**all-zero 禁止** |
| `attempt_id` | u32 BE | 同一 transfer の論理 attempt。初回 1。再 OFFER（payload 再送）で **+1**。0 禁止 |
| `content_digest` | 32-byte | payload bytes の **SHA-256** |
| `content_length` | u16 BE | payload の exact byte 長。0 は **空 payload 許可**（control marker）。digest は空入力の SHA-256 |
| `payload` | `content_length` bytes | single-frame body 内 |

**Bind 規則:** ACCEPT / REJECT / BUSY / evidence は `(custody_transfer_id, attempt_id, content_digest, content_length)` の **bit-exact 一致**を要求する（BUSY は attempt 一致 + transfer_id 一致; digest は OFFER 由来を echo）。

### 4.2 Single-frame 上限（fragmentation 非主張）

| 定数 | 値 | 根拠 |
| --- | ---: | --- |
| `NCL1_HEADER_BYTES` | 26 | 23章 |
| `MAX_NCL1_BODY` | 998 | 23章 |
| `CUSTODY_OFFER_FIXED` | 72 | §6.2 |
| `MAX_CUSTODY_PAYLOAD` | **926** | `998 - 72` |
| fragmentation | **非対応** | multi-frame / resume / offset フィールド **無し** |

`content_length > 926` → OFFER を **生成してはならない**（local reject `CUSTODY_LOCAL_TOO_LARGE`）。wire に partial payload を載せて後続 fragment を期待するプロトコルは **禁止**。

## 5. Message catalog（control protocol v2）

| message_type | 値 | body_length | 方向 | 相関 |
| --- | ---: | ---: | --- | --- |
| `CUSTODY_OFFER` | `0x30` | **exact 72 + content_length** | sender → receiver | request: nonzero `request_id` |
| `CUSTODY_ACCEPT` | `0x31` | **exact 56** | receiver → sender | response: echo `request_id` |
| `CUSTODY_REJECT` | `0x32` | **exact 60** | receiver → sender | response: echo |
| `CUSTODY_BUSY` | `0x33` | **exact 64** | receiver → sender | response: echo |

Role: **transfer の sender/receiver** は RuntimeRole と独立。Controller も Cell も sender になりうる（symmetric）。

逆の意味（receiver が OFFER を送る等）は **その transfer では** 単に role が逆。同一 session で双方向に **独立 transfer** を並行してよい（§10 上限内）。

## 6. Wire layout（big-endian; exact）

### 6.1 共通 header 規則

| 状態 | session_generation / cookie | request_id |
| --- | --- | --- |
| OFFER/ACCEPT/REJECT/BUSY | active と bit-exact | OFFER nonzero; 応答は echo |
| session 非 ACTIVE | 送受信禁止（reject STATE） | — |

flags = 0。reserved ≠ 0 → layout reject。

### 6.2 `CUSTODY_OFFER` body

```text
offset  size  end   field
0       16    16    custody_transfer_id      ≠0
16      4     20    attempt_id               u32 BE ≥1
20      32    52    content_digest           SHA-256(payload)
52      2     54    content_length           u16 BE; 0..926
54      2     56    flags                    u16 BE; exact 0
56      16    72    reserved0                exact 0（旧 sender_deadline_mono_ms は **廃止**; 比較用途禁止）
72      L     72+L  payload                  L = content_length
```

**OFFER fixed = 72 bytes。** digest は **payload only**。`sender_deadline_mono_ms` field は **存在しない**。

### 6.3 `CUSTODY_ACCEPT` body（56 bytes）

```text
offset  size  field
0       16    custody_transfer_id
16      4     attempt_id
20      32    content_digest
52      2     content_length
54      2     reserved                 exact 0
```

### 6.4 `CUSTODY_REJECT` body（60 bytes）

```text
offset  size  field
0       16    custody_transfer_id
16      4     attempt_id
20      32    content_digest
52      2     content_length
54      2     reject_code              u16 BE §6.6
56      4     reserved                 exact 0
```

### 6.5 `CUSTODY_BUSY` body（64 bytes）

```text
offset  size  field
0       16    custody_transfer_id
16      4     attempt_id
20      32    content_digest
52      2     content_length
54      2     reserved0                exact 0
56      4     retry_after_ms           u32 BE; 0 = 即 retry 可（なお backpressure 下）
60      4     reserved1                exact 0
```

BUSY は **durable commit しない**。receiver state は OFFER 受理前と同等（§7）。

### 6.6 `reject_code` closed

| 値 | 名前 | 意味 |
| ---: | --- | --- |
| `0x0001` | `CUSTODY_REJECT_DIGEST` | digest 不一致 |
| `0x0002` | `CUSTODY_REJECT_LENGTH` | length と payload 不一致 |
| `0x0003` | `CUSTODY_REJECT_DUPLICATE_CONFLICT` | 同一 transfer_id で異 digest/length |
| `0x0004` | `CUSTODY_REJECT_STATE` | 状態不正 / session |
| `0x0005` | `CUSTODY_REJECT_CAPACITY` | 上限（entries/bytes）— durable 予約不能 |
| `0x0006` | `CUSTODY_REJECT_STORAGE` | storage definite fail（IO_ERROR 等; UNKNOWN は §9） |
| `0x0007` | `CUSTODY_REJECT_EXPIRED` | TTL 超過 |
| `0x0008` | `CUSTODY_REJECT_UNSUPPORTED` | selected_control_version != 2 / too large / flags≠0 |
| `0x0009` | `CUSTODY_REJECT_LAYOUT` | reserved/layout |

## 7. Symmetric state model

### 7.1 Sender states（transfer ごと）

```text
S_NONE
  -- local create OFFER intent --> S_OFFER_PENDING
S_OFFER_PENDING
  -- raw TX accept OFFER --> S_OFFER_INFLIGHT
  -- WOULD_BLOCK --> stay（payload ownership は sender 保持）
  -- session fence --> S_NONE（inflight 破棄; durable sender evidence 無しなら payload 保持継続可）
S_OFFER_INFLIGHT
  -- RX ACCEPT matching bind --> S_ACCEPT_RX
  -- RX REJECT matching --> S_TERMINAL_REJECTED
  -- RX BUSY matching --> S_OFFER_PENDING（retry_after; attempt 維持または §8.4）
  -- timeout --> S_OFFER_PENDING（retry §8.4）
  -- session fence --> S_OFFER_PENDING（durable spool 保持; session 後 re-OFFER §8.4 / §12; **S_RECOVER_QUERY 状態は廃止**）
S_ACCEPT_RX
  -- sender FULL evidence commit STORAGE_OK --> S_RELEASE_OK
  -- sender FULL COMMIT_UNKNOWN --> S_EVIDENCE_UNKNOWN（§9）
  -- sender FULL definite fail --> S_EVIDENCE_FAIL（payload 保持; 再 evidence）
S_RELEASE_OK
  -- release policy RUN --> payload free --> S_TERMINAL_COMPLETE
  -- policy HOLD --> S_TERMINAL_COMPLETE_HELD_PAYLOAD
S_TERMINAL_*  （不変）
```

### 7.2 Receiver states（transfer ごと）

```text
R_NONE
  -- RX OFFER --> validate --> R_OFFER_EVAL
R_OFFER_EVAL
  -- capacity/TTL/layout fail --> TX REJECT or BUSY --> R_NONE
  -- begin FULL atomic group --> R_COMMITTING
R_COMMITTING
  -- FULL STORAGE_OK --> R_HELD + enqueue ACCEPT
  -- FULL COMMIT_UNKNOWN --> R_COMMIT_UNKNOWN（§9; ACCEPT 送らない）
  -- FULL definite fail --> R_NONE + REJECT STORAGE
R_HELD
  -- ACCEPT raw TX accept --> R_HELD_NOTIFIED
  -- WOULD_BLOCK --> stay R_HELD（owned durable; ACCEPT 再送可）
  -- session fence --> R_HELD（**durable は session に縛られない**; §7.3）
  -- **MUST NOT TTL-delete payload**（§7.6）
R_HELD_NOTIFIED
  -- duplicate OFFER same bind --> idempotent ACCEPT（§8.1）
  -- conflict OFFER --> REJECT DUPLICATE_CONFLICT
  -- upper handoff FULL OK --> R_HANDED_OFF（§7.6）
  -- accept_notify budget 尽きた --> stay R_HELD_NOTIFIED + counter; **payload 保持**
R_HANDED_OFF
  -- post-handoff retention 後 policy release --> R_TERMINAL_RELEASED
  -- MUST NOT auto-delete before handoff evidence
R_COMMIT_UNKNOWN
  -- recovery §9 / §12 --> R_HELD または R_NONE; **ACCEPT は FULL OK 後のみ**
R_DISCARDED_EXPLICIT
  -- explicit discard API only（責任終了の例外経路; §7.6）
R_TERMINAL_RELEASED
```

### 7.3 Session と durable の寿命差（exact）

| データ | session fence で消えるか |
| --- | --- |
| inflight OFFER request_id map | **消える** |
| raw / NCL1 volatile queues | **消える** |
| receiver **R_HELD durable custody group** | **消えない**（storage 正本） |
| sender **evidence durable** | **消えない** |
| sender 未 complete の payload spool（NCP1） | **消えない**。**FULL durable 必須**（§11.3）。**memory-only policy で ownership/custody 完了を主張禁止** |

再 HELLO 後:

- receiver は同一 `custody_transfer_id` の duplicate OFFER に **idempotent ACCEPT** できる（R_HELD）。
- sender は evidence 未完了なら **同一 transfer_id・新 attempt_id** で再 OFFER してよい（§8.4）。

### 7.4 Linearization（receiver; exact）

同一 step 内の順序（短縮禁止）:

1. NCL1 validation + v2 binding
2. OFFER layout / digest(payload) / length
3. capacity / TTL admission
4. **FULL atomic group commit**
5. commit 結果が `STORAGE_OK` のときだけ ACCEPT enqueue
6. `COMMIT_UNKNOWN` のとき ACCEPT **禁止**
7. definite fail のとき REJECT

**MUST NOT:** FULL 前に ACCEPT を enqueue / raw send。

### 7.5 Linearization（sender）

1. ACCEPT の bind 一致検査
2. **その後** evidence FULL commit
3. `STORAGE_OK` 後にだけ release policy 実行

ACCEPT raw 観測だけでは payload を削除しない。

### 7.6 Custody 責任の終了条件と GC 禁止（exact）

**Custody 責任（receiver）** は R_HELD / R_HELD_NOTIFIED にある間、**payload + NCT1 record を onward handoff 前に消してはならない。**

| 終了条件 | 次状態 | payload 削除してよいか |
| --- | --- | --- |
| Upper layer **handoff API** が handoff evidence を **FULL `STORAGE_OK`** で commit（§11.1） | `R_HANDED_OFF` | handoff 成功後、**post-handoff retention** 経過後のみ（default **0 ms** = handoff 直後可） |
| Explicit **discard API**（operator / capacity reclaim; reason 必須）が FULL で discard marker を commit | `R_DISCARDED_EXPLICIT` | discard commit 成功後のみ |
| Sender 側 S_TERMINAL_* | receiver 責任は **自動終了しない** | receiver は handoff/discard まで保持 |

**禁止:**

1. `TTL after R_HELD` で payload / NCT1 を **GC 削除**すること（旧誤記; 本 freeze で廃止）
2. accept_notify timeout だけで `R_TERMINAL_RELEASED` にすること
3. Application Receipt 未到達を理由に silent delete すること
4. session fence / reboot で durable custody を落とすこと

**TTL の正しい意味（rename）:**

| timer | 既定 | 作用 |
| --- | ---: | --- |
| `accept_notify_retry_budget` | **8** 回 | ACCEPT 再送上限。尽きたら counter `custody_accept_budget_exhausted++`。**state は R_HELD_NOTIFIED 維持** |
| `accept_notify_retry_interval_ms` | **1000** | 再送間隔（monotonic） |
| `max_hold_without_handoff_ms` | **600000** | 超過で **operator counter / diagnostics** のみ。**自動 delete 禁止** |
| `post_handoff_retention_ms` | **0** | R_HANDED_OFF 後に payload を消してよい最短待ち |

## 8. Duplicate / conflict / ACK loss / reconnect / retry

### 8.1 Exact duplicate OFFER（digest/length）

receiver が R_HELD / R_HELD_NOTIFIED / R_HANDED_OFF で、OFFER の `(transfer_id, content_digest, content_length)` が held と **bit-exact 同一** → attempt 規則は §8.4。
digest または length が異なる → REJECT DUPLICATE_CONFLICT。held 不変。

### 8.2 Conflict

同一 `custody_transfer_id` で held と digest または length が異なる → REJECT DUPLICATE_CONFLICT。held 不変。

### 8.3 ACCEPT/REJECT loss

| 状況 | 回復 |
| --- | --- |
| ACCEPT 喪失（receiver R_HELD, sender still INFLIGHT） | sender timeout → 再 OFFER（§8.4）。receiver idempotent ACCEPT |
| REJECT 喪失 | sender timeout → 再 OFFER。receiver 再評価（容量等） |
| BUSY 喪失 | sender timeout → 再 OFFER |

### 8.4 Retry / attempt_id closed catalog（exact）

| 項目 | 規範 |
| --- | --- |
| `custody_ack_timeout_ms` | **3000**（receiver **local** monotonic; §10.5 clock_epoch） |
| `custody_retry_max` | **8** / transfer（超過 → S_TERMINAL_GAVE_UP; payload 保持; operator） |
| 再 OFFER（sender） | 同一 transfer_id・同一 payload/digest/length。`attempt_id' = attempt_id + 1`（`UINT32_MAX` で fail-closed） |
| request_id | 毎回新規 nonzero |
| BUSY `retry_after_ms` | sender は自 local clock で待つ（peer mono を絶対時刻比較しない） |

**Receiver が held 中に OFFER を受けたときの attempt_id 分岐（閉じた規則）:**

`held_attempt` = durable NCTC record の attempt_id。`recv_attempt` = OFFER.attempt_id。
前提: digest+length が held と **同一**（異なれば §8.2）。

| 比較 | 動作 | durable mutation | wire |
| --- | --- | --- | --- |
| `recv_attempt < held_attempt` | **stale attempt** | **mutation 0** | ACCEPT（echo **held_attempt** ではなく **recv_attempt** を echo し request 相関を保つ; または REJECT STATE — **採用: ACCEPT echo recv_attempt**, payload/held_attempt **不変**） |
| `recv_attempt == held_attempt` | **exact duplicate attempt** | **mutation 0**（accept_notified 既 1 でも payload 不変） | ACCEPT echo recv_attempt |
| `recv_attempt > held_attempt` | **higher attempt 同一 content** | §11.10 H1–H3: FULL attempt 更新 → OK なら ACCEPT; UNKNOWN は readback **full bind** `(transfer_id,attempt_id,digest,length)==expected` を host のみ success に可; **ESP は一致でも ACCEPT 禁止** | ACCEPT after FULL OK |

**整合:** equal/lower は **mutation なし**。higher だけが max attempt の durable 更新を行い、その更新と ACCEPT の順序は FULL 成功後。
**禁止:** higher attempt で mutation なし ACCEPT のみ（durable max が遅れ dual truth）。
**禁止:** lower attempt で held_attempt を下げること。

### 8.5 Reconnect

物理 link / session 再確立後も durable R_HELD と sender spool は §7.3。wire 再同期後に §8.3–8.4。

## 9. COMMIT_UNKNOWN 両 truth recovery

### 9.1 原則

`commit(FULL)` が `COMMIT_UNKNOWN` を返したら、実装は次の **両真理**を仮定する:

- T1: durable に **commit 済み**
- T2: durable に **未 commit**

**silent `STORAGE_OK` 扱い禁止。** ACCEPT を送ってはならない（receiver）。evidence 成功扱いで payload 削除禁止（sender）。

### 9.2 Receiver path

```text
R_COMMITTING --COMMIT_UNKNOWN--> R_COMMIT_UNKNOWN
  1. fence local volatile OFFER copy
  2. reopen/read storage by custody_transfer_id（provider API）
  3a. host FULL-capable: held record exact digest/length 存在
       --> R_HELD 候補; ACCEPT は **STORAGE_OK 経路で commit が確定した場合のみ**
  3b. 不在 --> R_NONE; sender 再 OFFER を待つ（BUSY/REJECT を推測送出禁止）
  3c. 破損 / 不一致 --> fail-closed CORRUPT; REJECT せず storage recovery
  3d. **ESP unattested（§9.4）: read-back 一致でも R_HELD success / ACCEPT 禁止**
       （COMMIT_UNKNOWN の T1 仮定を success に昇格しない）
```

### 9.3 Sender evidence path

```text
S_ACCEPT_RX --COMMIT_UNKNOWN--> S_EVIDENCE_UNKNOWN
  1. payload を削除しない
  2. evidence namespace を read-back
  3a. evidence 存在 exact --> S_RELEASE_OK
  3b. 不在 --> 再 evidence commit
  3c. 反復 UNKNOWN 超過（8 回）--> S_EVIDENCE_FAIL; operator; payload 保持
```

### 9.4 ESP 現状 — 成功 ACK 禁止の統一（[21章](21-m3-esp-idf-durable-storage.md)）

| media | `commit(FULL)` 結果 | R_HELD 遷移 | `CUSTODY_ACCEPT` TX | OFFER 応答 | sender evidence complete |
| --- | --- | --- | --- | --- | --- |
| host model / POSIX SQLite（FULL 契約準拠） | `STORAGE_OK` 可 | 許可 | FULL OK 後のみ | ACCEPT/REJECT/BUSY 規則どおり | FULL OK 後 |
| ESP flash **without** HIL attestation | **常に COMMIT_UNKNOWN**（または init で FULL 拒否） | **禁止** | **禁止**（成功 ACK ゼロ） | **exact `CUSTODY_REJECT` + `CUSTODY_REJECT_STORAGE`** のみ（BUSY に逃がして「後で成功しうる」と偽らない） | **禁止** |
| ESP after power-cut HIL PASS + attestation | 21章昇格後 `STORAGE_OK` 可 | 許可候補 | FULL OK 後のみ | 通常規則 | 許可候補 |

**統一 MUST（ESP unproven）:**

1. receiver は NCT1 を **成功確定した R_HELD として公開しない**
2. **`CUSTODY_ACCEPT` を enqueue / raw send しない**（counter `custody_esp_success_forbidden++`）
3. 受信 OFFER への唯一の成功風応答は **無い** — 確定応答は **REJECT STORAGE**
4. recovery（§12）は record が残っていても **ACCEPT を送らず**、unproven の間は R_NONE 相当 + REJECT STORAGE 継続
5. sender が ACCEPT を受けないため re-OFFER し、最終的に `S_TERMINAL_GAVE_UP` または operator — **false complete 禁止**


**read-back 一致でも昇格禁止（ESP unproven）:**
`commit(FULL)` が UNKNOWN のあと record が読めても、それは T1 の可能性に過ぎない。
**unattested media では ACCEPT / custody success / S_RELEASE_OK を発行してはならない。**
host FULL-capable のみ read-back 成功を STORAGE_OK 相当 recovery に使える。

**Blocker B-U6-ESP-FULL:** ESP 上で custody success / ACCEPT / R_HELD production を名乗るには 21章 power-cut HIL PASS と FULL attestation が必要。

## 10. Resource limits / backpressure / timers

### 10.1 Bounds（U6 profile default; 同一 PR で test 更新）

| 資源 | 上限 |
| --- | ---: |
| concurrent custody entries / Runtime role instance | **8** |
| total durable custody payload bytes | **8192** |
| single payload | **926** |
| `max_hold_without_handoff_ms` | **600000**（delete しない; §7.6） |
| `accept_notify_retry_budget` | **8** |
| sender local spool entries | **8** |
| sender local spool bytes | **8192** |
| inflight OFFER responses waiting（per session） | **4**（request_id map と共有; 総 inflight ≤8 with HELLO/PING/U5） |

超過 OFFER → BUSY（一時）または REJECT CAPACITY（予約不能が確定的）。**silent drop 禁止**。
**payload TTL GC は存在しない**（§7.6）。

### 10.2 Backpressure

1. raw TX full → WOULD_BLOCK（custody state は維持）。
2. logical ingress full → 新規 OFFER accept 拒否 + counter（frame は C3 所有規則に従う）。
3. backpressure を Application `PARKED_RETRY` や Receipt に **直接写像しない**。

### 10.3 Release policy（sender; wire 外; NCP1 `release_policy` と同一値空間）

| policy 値 | evidence FULL 成功後 | auto timer GC |
| --- | --- | --- |
| `REL_IMMEDIATE` (0) | 同一 FULL で `payload_present=0`（original digest/length 不変） | n/a（既に payload 無し） |
| `REL_AFTER_RETENTION` (1) | `payload_present=1` + retention anchor; **timer 満了後のみ** auto GC 可 | **yes**（§11.11.4–5） |
| `REL_HOLD` (2) | `NCP_RELEASE_HOLD` + `payload_present=1` + anchor 記録可 | **no**（自動 GC **禁止**） |

**REL_HOLD canonical:** payload/record は **明示 discard API** または **明示 release transition**（`G_RELEASE_HOLD_END` / 管理者 release; same FULL）まで保持。
retention anchor を持っても **GC permission にはしない**。NO_SPACE でも REL_HOLD を silent 破棄せず **BUSY / CAPACITY / fence**（backpressure）。

wire に policy を載せない（sender local）。receiver は peer policy を知らない。

### 10.4 Optional U5 capability gate

`CellOperatingAssignment` が ASSIGN_ACTIVE かつ `CAP_CUSTODY_ENDPOINT=0` のとき、実装は新規 OFFER を REJECT UNSUPPORTED してよい。assignment が NONE の LAB control-only では **default 許可**（capability 未設定 = 制限なし）。

### 10.5 Platform `clock_epoch_id`（128-bit; exact）

| 項目 | 規範 |
| --- | --- |
| 型 | platform **`ninlil_id128_t clock_epoch_id`**（[platform.h](../include/ninlil/platform.h); **exact 16 bytes**） |
| 供給 | Runtime/clock port が供給する **既存 authority** を **bit-exact コピー**して durable に書く |
| **禁止** | u64 への切詰め、独自 CSPRNG epoch authority、別乱数で clock_epoch を捏造 |
| 比較 | **同一 `clock_epoch_id` の mono_ms だけ**前後比較可 |
| reboot | platform が新 `clock_epoch_id` を出す。旧 epoch の mono 差分で TTL/deadline 計算 **禁止** |
| peer time | OFFER に peer mono deadline field **無し**（§6.2 reserved）。receiver が peer time で custody を捨てることを禁止 |
| custody drop | epoch 変化を理由に payload 削除 **禁止** |

## 11. Durable exact format（namespace / key / value / CRC）

### 11.0 Namespace budget（ESP 実契約へ収容; exact）

[21章](21-m3-esp-idf-durable-storage.md): namespaces **hard max 4** / **production default 2**。Runtime domain が既に namespace を使うため、U5+U6 が **4 本の専用 namespace**を増やす設計は **production default で破綻**する。

| 項目 | 規範 |
| --- | --- |
| **採用** | **Ninlil control 共用 1 namespace** exact name **`ninlil.ctl.v1`** |
| 同居 | U5 ARW（kind `ARW1`）+ U6（`NCT1`/`NCH1`/`NCS1`/`NCP1`/`NCD1`/`NCT0`）を **同一 namespace** 内で key-space 分離 |
| Runtime 共存 | Runtime domain/store は **別 namespace**（最大もう 1 本）。production default 2 = `{runtime_ns, ninlil.ctl.v1}` |
| **禁止** | `ninlil.u6.nct1.v1` 等の **record 種別ごとの namespace増殖**（旧設計） |
| open handles | control path 全体で **RW txn ≤ 1**、**RO txn ≤ 1**、**iter ≤ 1**（U5 ARW と共有） |
| max keys | **32**（production committed entry capacity と整合） |
| max concurrent transfer_id | **8** |
| max ARW keys | **4**（[25章 §7.6.7](25-u5-cell-operating-assignment.md)） |
| entry 予算例 | 8×(NCT1+NCP1) + 4 ARW = 20 ≤ 32（NCH1/NCS1 は handoff/evidence 時のみ追加; 合計 32 超過 put は NO_SPACE / REJECT CAPACITY） |

**禁止:** 5-byte 文字列 `NCTC1` を magic に使うこと。

### 11.1 Canonical key table（`ninlil.ctl.v1` 唯一; kind 別 exact）

**禁止:** 「全 kind が 20B」という旧要約。kind ごとに **key_bytes 長が異なる**。
**正本:** 本表 + [25章 §7.6.3](25-u5-cell-operating-assignment.md)（ARW）。両章が矛盾する場合は **本表を先に直し、25 と同一に保つ**。

| kind | key_bytes | layout (offset/size/end) | id 内容 | value 正本 | scan prefix |
| --- | ---: | --- | --- | --- | --- |
| `ARW1` | **36** | `0/4/4 kind; 4/16/20 site_domain_id; 20/16/36 recipient_device_id` | site + recipient（≠0） | [25章 §7.6.3](25-u5-cell-operating-assignment.md) 172B | first 4B = `ARW1` |
| `NCT1` | **20** | `0/4/4 kind; 4/16/20 transfer_id` | transfer_id ≠0 | §11.2 | `NCT1` |
| `NCP1` | **20** | same as NCT1 pattern | transfer_id ≠0 | §11.3 | `NCP1` |
| `NCS1` | **20** | same | transfer_id ≠0 | §11.4 | `NCS1` |
| `NCH1` | **20** | same | transfer_id ≠0 | §11.5 | `NCH1` |
| `NCD1` | **20** | same | transfer_id ≠0 | §11.5.2 | `NCD1` |
| `NCT0` | **20** | same | transfer_id ≠0 | §11.11 | `NCT0` |

**Scan / foreign / unknown:**

1. namespace 全 key を enumerate（bounded ≤32）
2. key 長 ∉ {20,36} → **FOREIGN_CORRUPT**（isolate; silent drop 禁止）
3. key 長 36 かつ prefix ≠ `ARW1` → FOREIGN_CORRUPT
4. key 長 20 かつ prefix が上表 kind 以外 → FOREIGN_CORRUPT（将来 kind は別 freeze）
5. key 長 20 かつ prefix=`ARW1` → CORRUPT（ARW は 36B のみ）
6. key 長 36 かつ prefix が custody kind → CORRUPT
7. ARW scan は prefix `ARW1` のみ; custody scan は 20B kinds のみ

**ARW anti-replay:** recipient は key に含まれるため、site だけ key にする実装は **非準拠**（identity/recipient を失わない）。

### 11.2 NCT1 value（held; BE; CRC32C）

```text
offset  size  end   field
0       4     4     magic                   exact "NCT1"
4       4     8     format_version          u32 BE = 1
8       16    24    custody_transfer_id     = key id
24      4     28    attempt_id              u32 BE ≥1
28      32    60    content_digest
60      2     62    content_length          0..926
62      1     63    accept_notified         u8 0|1
63      1     64    handoff_complete        u8 0|1
64      8     72    received_mono_ms        u64 BE
72      16    88    received_clock_epoch_id id128 BE（§10.5; **16B bit-exact**）
88      4     92    header_crc32c           CRC32C([0..88))
92      L     92+L  payload
92+L    4     96+L  payload_crc32c
```

算術 fixed meta **92** + L + 4。u64 clock epoch **禁止**。

### 11.3 NCP1 value（sender pending / terminal; FULL 必須; format_version **2**）

**Offer bind 不変規則（§4.1 と同一 bind）:**
`content_digest` / `content_length` は **初回 OFFER_PENDING 書込時の payload に対する SHA-256 と byte 長**であり、以後 **state が terminal になっても bit-exact 不変**。
NCS1 / ACCEPT evidence / duplicate ACK の bind は常にこの **original digest+length**（+ transfer_id + attempt_id）を使う。
payload の有無は **`payload_present`** が sole authority（length=0 で digest を書き換えない）。

```text
offset  size  end   field
0       4     4     magic                   exact "NCP1"
4       4     8     format_version          u32 BE = **2**
8       16    24    custody_transfer_id
24      4     28    attempt_id              u32 BE ≥1
28      32    60    content_digest          original offer bind; IMMUTABLE after first put
60      2     62    content_length          original offer bind; IMMUTABLE; 0..926
62      2     64    state_code              §11.6
64      1     65    retry_budget_remaining  u8
65      1     66    release_policy          §11.6.1
66      1     67    payload_present         u8 exact 0 or 1
67      1     68    reserved0               exact 0
68      8     76    local_mono_ms           last mutation sample
76      16    92    local_clock_epoch_id    id128 platform bit-exact §10.5
92      8     100   retention_anchor_mono_ms  u64 BE; 0 = unset
100     16    116   retention_anchor_clock_epoch_id  id128; all-zero = unset
116     4     120   header_crc32c           CRC32C([0..116))
120     L     120+L payload_bytes           L = content_length if payload_present==1 else **0**
120+L   4     124+L payload_crc32c          CRC32C(payload_bytes); L=0 → CRC32C(empty)
```

算術 header **120** + L + 4。format_version≠2 → UNKNOWN_SCHEMA。

**Validation（閉じた規則）:**

| 条件 | 結果 |
| --- | --- |
| `payload_present==1` | L must == `content_length`; SHA-256(payload_bytes)==`content_digest` |
| `payload_present==0` | L must == 0; **content_digest/length は original のまま**（empty digest に書き換え禁止） |
| state ∈ non-terminal かつ payload_present==0 | CORRUPT（OFFER/ACCEPT_RX 中に payload 欠落禁止） |
| state ∈ {TERMINAL_COMPLETE, RELEASE_HOLD, …} | payload_present は policy に従う §11.10 |

**MUST:** complete まで FULL durable。**MUST NOT:** memory-only ownership。
**MUST NOT:** terminal 化で `content_digest`/`content_length` を empty 用に書き換える。

### 11.4 NCS1 value（sender evidence）

bind fields `content_digest`/`content_length` は **NCP1 original offer bind** と bit-exact（payload_present 非依存）。

```text
offset  size  end   field
0       4     4     magic                   "NCS1"
4       4     8     format_version          = 1
8       16    24    custody_transfer_id
24      4     28    attempt_id
28      32    60    content_digest
60      2     62    content_length
62      2     64    reserved0               0
64      8     72    evidence_mono_ms
72      16    88    evidence_clock_epoch_id id128
88      4     92    crc32c                  CRC32C([0..88))
```

固定 **92** bytes。

### 11.5 NCH1 value（handoff evidence）

```text
offset  size  end   field
0       4     4     magic                   "NCH1"
4       4     8     format_version          = 1
8       16    24    custody_transfer_id
24      32    56    content_digest
56      2     58    content_length
58      2     60    reserved0               0
60      8     68    handoff_mono_ms
68      16    84    handoff_clock_epoch_id  id128
84      4     88    crc32c                  CRC32C([0..84))
```

固定 **88** bytes。

### 11.5.1 Handoff completion FULL（同一 transaction; exact）

R_HELD* → R_HANDED_OFF は **1 FULL txn** で:

1. put **NCH1** VALID（bind = transfer_id+digest+length）
2. put **NCT1** 同一 transfer_id で `handoff_complete=1`（payload 維持）
3. commit(FULL)

| 結果 | 状態 |
| --- | --- |
| STORAGE_OK | R_HANDED_OFF |
| COMMIT_UNKNOWN | 両 truth: read both NCH1+NCT1; 両方新 → handed; 両方旧 → not; **mixed → CORRUPT/fail-closed**。ACCEPT 経路と無関係。ESP unattested: success 禁止 |
| fail | 旧状態 |

**MUST NOT:** NCH1 only または handoff_complete only を success とする。

### 11.5.2 Explicit discard marker **NCD1**（exact; **single canonical** path）

**Key:** exact **20**B = `NCD1`(4) || transfer_id(16) ≠0。

**Value**（exact **108** bytes; multi-byte **unsigned big-endian**）:

```text
offset  size  end   field
0       4     4     magic                   exact "NCD1"
4       4     8     format_version          u32 BE = 1
8       2     10    value_length            u16 BE = exact 108
10      2     12    reserved0               exact 0
12      16    28    custody_transfer_id     = key id
28      32    60    content_digest          discarded bind
60      2     62    content_length
62      2     64    discard_reason          u16 BE §11.5.3
64      16    80    authority_actor_id      16B opaque ≠ all-zero
80      8     88    retention_anchor_mono_ms  u64 BE ≥0
88      16    104   retention_anchor_clock_epoch_id  id128 ≠ all-zero
104     4     108   crc32c                  CRC32C([0..104))
```

算術: `4+4+2+2+16+32+2+2+16+8+16+4 = 108`。
CRC coverage **exact [0,104)**。anchor は discard FULL 時の platform sample（§10.5）。

**Canonical discard FULL（二択禁止; 唯一方式）:**

同一 FULL txn で **exact 順序**:

1. put **NCD1** VALID
2. **delete** NCT1 key（存在すれば）
3. put **NCT0** tombstone VALID（§11.11 exact layout）
4. commit(FULL)

**禁止:** empty-payload NCT1 を残す代替、NCD1 only、NCT0 only、delete without NCT0。

| commit 結果 | 解釈 |
| --- | --- |
| STORAGE_OK | discarded; RAM R_DISCARDED_EXPLICIT |
| COMMIT_UNKNOWN | §12.4 both-truth: NCD1+NCT0 両方新 / 両方旧 / mixed→CORRUPT |
| fail | 旧状態 |

ESP unattested: success 禁止。

### 11.5.3 discard_reason closed

| 値 | 名前 |
| ---: | --- |
| 1 | `DISCARD_OPERATOR` |
| 2 | `DISCARD_CAPACITY` |
| 3 | `DISCARD_EXPIRED_POLICY`（責任終了後の policy のみ; TTL 単独禁止） |
| 4 | `DISCARD_CORRUPT_RECOVERY` |

### 11.6 NCP1 state_code closed（persist）

| 値 | 名前 | boot 後 |
| ---: | --- | --- |
| 1 | `NCP_OFFER_PENDING` | re-OFFER 可 |
| 2 | `NCP_OFFER_INFLIGHT` | re-OFFER attempt+1 または resolve |
| 3 | `NCP_ACCEPT_RX` | evidence FULL retry |
| 4 | `NCP_EVIDENCE_UNKNOWN` | evidence recovery |
| 5 | `NCP_EVIDENCE_FAIL` | operator; hold payload |
| 6 | `NCP_TERMINAL_REJECTED` | no re-OFFER; GC eligibility §11.11 |
| 7 | `NCP_TERMINAL_GAVE_UP` | retry_budget 0; no re-OFFER |
| 8 | `NCP_RELEASE_HOLD` | evidence OK; **payload 保持; auto GC 不可**; 明示 release/discard のみ |
| 9 | `NCP_TERMINAL_COMPLETE` | release done; tombstone 可 |

#### 11.6.1 release_policy u8

| 値 | 名前 |
| ---: | --- |
| 0 | `REL_IMMEDIATE` |
| 1 | `REL_AFTER_RETENTION` |
| 2 | `REL_HOLD` |

### 11.7 Classification on read

| 結果 | 条件 |
| --- | --- |
| VALID | magic/version/CRC/key==id/invariants OK |
| PARTIAL | short / torn |
| CORRUPT | CRC/invariant fail |
| UNKNOWN_SCHEMA | bad magic/version |

### 11.8 Global single RW commit slot + capacity

| 項目 | 規範 |
| --- | --- |
| max concurrent transfer_id | **8** |
| single global RW commit slot | **1** |
| max keys | **32**（ARW+U6; NO_SPACE 時 §11.11） |
| handles | RW≤1 RO≤1 iter≤1 |

### 11.10 Wire observation vs FULL state updates（exact order）

**Receiver first accept (new hold):**

```text
R1 validate OFFER
R2 FULL put NCT1 (accept_notified=0, handoff=0, payload)
R3 STORAGE_OK → R_HELD; UNKNOWN → no ACCEPT（ESP: never success）
R4 enqueue ACCEPT
R5 raw TX accept ACCEPT
R6 FULL put NCT1 accept_notified=1（only after R5）
R7 R6 UNKNOWN → leave accept_notified=0; re-OFFER で idempotent ACCEPT
```

**Receiver higher attempt (same digest/length):**

```text
H1 validate
H2 FULL put NCT1 attempt_id=recv（payload 不変）
H3 OK → ACCEPT; UNKNOWN → compare readback **full bind**
    (transfer_id, attempt_id, digest, length) == expected_new
    host match → treat OK; ESP match → still no ACCEPT success
```

**Sender OFFER path:**

```text
S1 FULL NCP1 state=OFFER_PENDING + payload
S2 enqueue OFFER
S3 raw TX accept → FULL state=OFFER_INFLIGHT
S4 S3 UNKNOWN → readback state; ESP no false complete
```

**Sender ACCEPT observed → evidence → terminal/release（exact FULL groups）:**

```text
A1 validate ACCEPT bind == NCP1 original (transfer_id, attempt_id, content_digest, content_length)
A2 FULL atomic group G_ACCEPT:
     NCP1.state_code = ACCEPT_RX
     content_digest/length/payload_present=1/payload 不変
     retry_budget_remaining 不変
     local_mono + local_clock_epoch_id = platform sample
   → OK / UNKNOWN / fail per matrix
A3 FULL atomic group G_EVIDENCE（NCS1 + NCP1 同一 txn; payload 削除も同一 group）:
     put NCS1 bind = (transfer_id, attempt_id, content_digest, content_length)  # original
     sample = platform (clock_epoch_id, mono_ms)
     if release_policy == REL_HOLD:
        NCP1.state = NCP_RELEASE_HOLD
        payload_present = 1  # payload 保持; auto GC 不可
        retention_anchor_* = sample  # diagnostics/max-hold only; **not** GC permission
     if release_policy == REL_IMMEDIATE:
        NCP1.state = NCP_TERMINAL_COMPLETE
        payload_present = 0  # payload_bytes 除去; digest/length IMMUTABLE
        retention_anchor_* = sample
        # optional same txn: put NCT0 TERM_SENDER_COMPLETE
     if release_policy == REL_AFTER_RETENTION:
        NCP1.state = NCP_TERMINAL_COMPLETE
        payload_present = 1  # retention 満了まで payload 保持
        retention_anchor_* = sample  # retention 起点
   commit(FULL)
   STORAGE_OK → done
   COMMIT_UNKNOWN → readback exact expected NCP1(full header+payload_present+payload)+NCS1;
                    host both match → success; mixed/partial → CORRUPT or retry; ESP never promote
```

**Sender REJECT / budget exhaust（exact）:**

```text
X1 REJECT wire or timeout with retry_budget_remaining==0
X2 FULL G_TERMINAL:
     state = TERMINAL_REJECTED | TERMINAL_GAVE_UP
     GAVE_UP ⇒ retry_budget_remaining = 0; REJECT ⇒ budget 不変
     payload_present = 1（payload 保持）
     content_digest/length IMMUTABLE
     retention_anchor_* = platform sample  # GC/retention 起点
     local_mono/epoch = sample
   commit(FULL)
X3 UNKNOWN → readback full NCP1 == expected terminal value
```

**Timeout with budget>0:**

```text
T1 budget' = budget - 1
T2 FULL: attempt_id+1, state=OFFER_PENDING, budget', payload_present=1, same payload,
     retention_anchor unset (0), local sample update
T3 budget durable; never reset to profile max on reboot
```

**REL_HOLD → explicit release later:**

```text
H1 FULL G_RELEASE_HOLD_END:
     state=TERMINAL_COMPLETE, payload_present=0, retention_anchor refresh sample,
     put NCT0 TERM_SENDER_COMPLETE same txn
```

**MUST NOT:** ACCEPT bind に empty digest を使う。
**MUST NOT:** payload 削除と terminal state を別 FULL に分ける（G_EVIDENCE / G_RELEASE_HOLD_END は同一 group）。
**MUST NOT:** restart で budget を profile max に戻す。

### 11.11 Terminal retention / tombstone **NCT0** / GC（責任を消さない）

#### 11.11.1 NCT0 exact layout（**88** bytes; BE）

**Key:** exact 20B = `NCT0`(4) || transfer_id(16)。

```text
offset  size  end   field
0       4     4     magic                   exact "NCT0"
4       4     8     format_version          u32 BE = 1
8       16    24    custody_transfer_id     = key id
24      32    56    content_digest
56      2     58    content_length
58      1     59    terminal_class          u8 closed §11.11.2
59      1     60    reserved0               exact 0
60      8     68    retention_anchor_mono_ms  u64 BE
68      16    84    retention_anchor_clock_epoch_id  id128 ≠0
84      4     88    crc32c                  CRC32C([0..84))
```

算術: `4+4+16+32+2+1+1+8+16+4 = 88`。
CRC coverage **exact [0,84)**。anchor は terminal/discard FULL 時 sample。

#### 11.11.2 terminal_class closed

| 値 | 名前 |
| ---: | --- |
| 1 | `TERM_HANDOFF` |
| 2 | `TERM_DISCARD` |
| 3 | `TERM_SENDER_COMPLETE` |
| 4 | `TERM_SENDER_REJECTED` |
| 5 | `TERM_SENDER_GAVE_UP` |

#### 11.11.3 Retention / GC order（exact）

| record | 保持 |
| --- | --- |
| NCT1 held | discard/handoff FULL まで削除禁止 |
| NCH1 | NCT0 TERM_HANDOFF まで |
| NCD1 | 常に discard 証跡; GC は NCT0 後 optional delete |
| NCS1/NCP1 terminal | NCT0 TERM_SENDER_* まで |

**GC FULL 順序（eligible transfer）:**

1. eligibility check
2. ensure NCT0 VALID（無ければ encode+put）
3. delete NCP1, NCS1, NCH1, NCT1, optionally NCD1
4. commit(FULL)

**eligibility クラス（閉じた表）:**

| 対象 | auto timer GC | 明示 operator GC / discard |
| --- | --- | --- |
| NCT1 R_HELD / R_HELD_NOTIFIED | **no** | discard FULL only |
| NCP `NCP_RELEASE_HOLD`（REL_HOLD） | **no**（anchor あっても **no**） | **yes** — `G_RELEASE_HOLD_END` または explicit discard 相当 FULL |
| NCP `TERMINAL_COMPLETE` かつ `release_policy==REL_AFTER_RETENTION` かつ `payload_present==1` | **yes** if §11.11.4 elapsed | yes |
| NCP `TERMINAL_COMPLETE` かつ `payload_present==0` | n/a（payload 済）; record tombstone GC yes after elapsed | yes |
| NCP TERMINAL_REJECTED / GAVE_UP | yes after elapsed（record 証跡の tombstone） | yes |
| receiver handoff 完了 + NCH1 | yes after elapsed | yes |
| NCD1 discard 済み | yes after elapsed | yes |

**auto timer GC eligibility AND（REL_HOLD を含めない）:**

1. class が上表 **auto timer GC = yes**
2. **retention anchor 経過**（§11.11.4）
3. NCT0 VALID（本 txn で作成可）

**NO_SPACE:** oldest **auto-eligible** transfer_id LE から GC。0 eligible → REJECT CAPACITY / BUSY。
**MUST NOT:** `NCP_RELEASE_HOLD` や held NCT1 を capacity 理由で silent 破棄。REL_HOLD は backpressure（新規 OFFER BUSY/CAPACITY）で守る。

#### 11.11.4 Retention elapsed（clock-safe; exact）

`anchor = (retention_anchor_clock_epoch_id, retention_anchor_mono_ms)` from NCD1 / NCT0 / NCP1 / NCH1（handoff は NCH1.handoff_*）。
`now = platform (clock_epoch_id, mono_ms)`。

| 条件 | elapsed 計算 | auto GC |
| --- | --- | --- |
| same `clock_epoch_id` bit-exact かつ mono 単調 | `now.mono - anchor.mono`（underflow → not） | only if class allows timer GC **and** ≥ `post_terminal_retention_ms`（default **60000**） |
| epoch mismatch / reboot 新 epoch / untrusted | **計算しない** | **no**（SAFE_HOLD） |
| same epoch rollback（now.mono < anchor.mono） | not elapsed | no |
| operator explicit GC / REL_HOLD explicit release | n/a | **yes**（timer 不要; REL_HOLD の **唯一**の解放経路の一つ） |

**REL_HOLD:** anchor は diagnostics / max-hold metrics 用に保持してよいが **auto GC permission を与えない**。
**re-anchor:** SAFE_HOLD 中は operator 明示 FULL のみ。silent re-anchor 禁止。
**overflow:** non-eligible（含む REL_HOLD / held）は削除せず backpressure。
## 12. Boot / process recovery（exact algorithm）

起動時（storage open 成功後）に **exact 1 回**。推測 state 禁止。

### 12.1 Receiver reconstruction（NCT1/NCH1/NCD1/NCT0）

```text
1. open `ninlil.ctl.v1`; enumerate all keys（≤32）
2. classify each key by §11.1 (length+prefix); foreign → isolate
3. for each NCT0 VALID: mark transfer terminal_class; no ACCEPT
4. for each NCD1 VALID:
   - if NCT0 TERM_DISCARD missing → CORRUPT or schedule repair txn（host only）
   - RAM R_DISCARDED_EXPLICIT; never ACCEPT
5. for each NCT1 VALID:
   a. invariants: key id match, attempt≥1, payload digests, flags 0/1
   b. if NCD1 or NCT0 for same id → ignore NCT1 residual as stale CORRUPT candidate（cleanup GC）
   c. handoff_complete==1 ⇒ require NCH1 VALID else CORRUPT
   d. else accept_notified 0/1 → R_HELD / R_HELD_NOTIFIED
6. for each NCH1 without NCT1/NCT0: keep as evidence; no ACCEPT
7. ESP unattested: never ACCEPT/success; OFFER→REJECT STORAGE
8. host + session: re-OFFER 待ち idempotent ACCEPT only
```

### 12.2 Sender reconstruction（NCP1/NCS1/NCT0）

```text
1. enumerate NCP1/NCS1/NCT0
2. NCP1 VALID:
   - restore state_code, attempt_id, retry_budget_remaining, release_policy, payload
   - budget は durable 値（profile max へ reset 禁止）
   - state OFFER_* → session 後 re-OFFER（attempt 維持 or +1 per §11.10 T*）
   - ACCEPT_RX / EVIDENCE_* → evidence retry; payload 保持
   - TERMINAL_COMPLETE / REJECTED / GAVE_UP → no re-OFFER; timer GC only if class allows（§11.11.3）
   - NCP_RELEASE_HOLD → no re-OFFER; **auto GC 不可**; 明示 G_RELEASE_HOLD_END / discard 待ち
3. NCS1 without NCP1 + NCT0 → complete
4. NCS1 without NCP1 without NCT0 → treat evidence-only; host may synthesize COMPLETE+NCT0
5. ESP: no complete claim
```

### 12.3 COMMIT_UNKNOWN recovery matrix（control records）

| pending FULL | readback | host action | ESP |
| --- | --- | --- | --- |
| ARW L6 | full value == expected | promote active/ACK | **never promote** |
| discard NCD1+NCT0 | both new / both old / mixed | success / retry / CORRUPT | never success |
| handoff NCH1+NCT1 | both new / both old / mixed | same | never success |
| NCP terminal / G_EVIDENCE | full NCP1（digest/length/payload_present/payload/anchors/state）+NCS1 | success if bit-exact expected | never success |
| higher attempt NCT1 | full bind includes attempt_id | success if match | never success |
| retention anchor write | record full value including anchors | success if match | never success |

### 12.4 Re-ACK / re-OFFER after recovery

| 復元状態 | session 後 |
| --- | --- |
| R_HELD / R_HELD_NOTIFIED（host） | peer re-OFFER → idempotent ACCEPT |
| NCP OFFER_* | re-OFFER; budget 不変 except T-path durable decrement |
| NCP ACCEPT_RX | evidence FULL retry |
| terminal / discarded | no re-OFFER |
| NCP_RELEASE_HOLD | no re-OFFER; hold until explicit release FULL |
| ESP any | ACCEPT success 禁止 |

**S_RECOVER_QUERY は定義しない。** 収束は OFFER/ACCEPT/REJECT/BUSY + durable recovery のみ。

## 13. Private API 境界

| 項目 | 規範 |
| --- | --- |
| copy-in | OFFER API は payload を call 中に spool へ copy。成功前に caller buffer 依存しない |
| copy-out | take/query は caller buffer へ copy-out |
| sole drive | `runtime_step` / pump / owner step のみ reducer 進行 |
| WOULD_BLOCK | TX/storage busy |
| pointer 借用 | step を跨ぐ禁止 |
| public ABI | 非露出 |

## 14. Structured counters

| counter | 意味 |
| --- | --- |
| `custody_offer_rx` / `custody_offer_tx` | OFFER |
| `custody_accept_tx` / `custody_accept_rx` | ACCEPT |
| `custody_reject_*` | reason 別 |
| `custody_busy_tx` | BUSY |
| `custody_full_ok` | FULL STORAGE_OK |
| `custody_commit_unknown` | UNKNOWN |
| `custody_duplicate_accept` | idempotent ACCEPT |
| `custody_conflict` | conflict reject |
| `custody_retry` | sender re-OFFER |
| `custody_payload_release` | §14.1 closed increment table（handoff/discard **以外**の sender release を含む） |
| `custody_accept_budget_exhausted` | ACCEPT 再送 budget 尽きた（payload 保持） |
| `custody_hold_without_handoff` | max_hold 超過 diagnostics |
| `custody_esp_success_forbidden` | ESP unproven path で ACCEPT/success を拒否 |


### 14.1 `custody_payload_release` closed increment table（private stats; public ABI 非露出）

**scope:** control-plane private counter（public `include/ninlil` registry には載せない。将来 public 化する場合は別名 + migration）。
**単位:** 1 logical payload 解放成功あたり **exact +1**（duplicate / recovery 再実行では +0）。

| 事象 | role | +1 条件 | +0（必須） |
| --- | --- | --- | --- |
| receiver handoff FULL OK（R_HANDED_OFF; post-handoff payload 削除成功時） | receiver | first successful payload free after handoff | 二重 handoff / UNKNOWN 再読 |
| receiver explicit discard FULL OK（NCD1+NCT0; NCT1 payload 削除） | receiver | first successful discard free | 再 discard / UNKNOWN |
| sender `G_EVIDENCE` REL_IMMEDIATE: `payload_present` 1→0 同一 FULL OK | sender | first transition | COMMIT_UNKNOWN 再試行成功時は expected 一致なら **idempotent +0**（既に 0 なら +0） |
| sender `REL_AFTER_RETENTION` timer GC: `payload_present` 1→0 FULL OK | sender | first free | re-GC |
| sender `G_RELEASE_HOLD_END`: HOLD→COMPLETE + payload_present 0 FULL OK | sender | first free | reentry |
| sender REJECT/GAVE_UP（payload 保持） | sender | **never** | — |
| NCP_RELEASE_HOLD 滞在中 | sender | **never**（auto GC なし） | — |
| recovery / COMMIT_UNKNOWN readback success で既に payload_present=0 | any | **+0** | 再カウント禁止 |

**命名:** 旧称 `custody_release`（handoff/discard only）は **廃止**。実装・test は `custody_payload_release` のみ。

## 15. Vector set（Required at U6 implementation）

### 15.1 Host pure / SQLite crash injection（必須）

| ID | 内容 |
| --- | --- |
| `U6-G-OFFER-ACCEPT-EVIDENCE-RELEASE` | happy path dual FULL + handoff then release |
| `U6-G-EMPTY-PAYLOAD` | length 0 |
| `U6-G-MAX-PAYLOAD-926` | exact 926 |
| `U6-G-DUP-OFFER-IDEMPOTENT` | duplicate ACCEPT |
| `U6-G-ACCEPT-LOSS-RETRY` | ACCEPT 喪失 → re-OFFER → complete |
| `U6-G-BUSY-THEN-OK` | BUSY → retry → OK |
| `U6-G-BIDIR-INDEPENDENT` | 双方向同時 transfer 2 件 |
| `U6-G-SESSION-FENCE-HELD` | session fence 後 durable R_HELD 維持 + re-OFFER ACCEPT |
| `U6-G-NO-TTL-GC` | max_hold 超過でも payload 残存; handoff 前 delete 0 |
| `U6-G-BOOT-RECONSTRUCT-HELD` | reboot → R_HELD; re-OFFER → ACCEPT |
| `U6-G-BOOT-SENDER-REOFFER` | reboot sender spool → re-OFFER |
| `U6-C-CRASH-BEFORE-FULL` | receiver crash before commit → no ACCEPT; re-OFFER |
| `U6-C-CRASH-AFTER-FULL-BEFORE-ACCEPT-TX` | R_HELD; re-OFFER ACCEPT |
| `U6-C-CRASH-AFTER-ACCEPT-BEFORE-EVIDENCE` | sender re-evidence; no double free |
| `U6-C-COMMIT-UNKNOWN-RECEIVER` | both-truth recovery 3a/3b |
| `U6-C-COMMIT-UNKNOWN-SENDER` | evidence recovery |
| `U6-N-DIGEST` | bad digest |
| `U6-N-TOO-LARGE` | 927 reject local |
| `U6-N-FRAGMENT-CLAIM` | multi-frame 非実装（unsupported） |
| `U6-N-ACCEPT-BEFORE-FULL` | model mutation: 禁止順序 detect |
| `U6-N-RAW-CDC-NOT-SUCCESS` | write accept のみで complete にならない |
| `U6-N-RECEIPT-NOT-AUTO` | custody complete で Receipt stage 非上昇 |
| `U6-N-V1-SESSION` | control_version 1 reject |
| `U6-N-CONFLICT-DIGEST` | same id different digest |
| `U6-N-CAPACITY` | 9th entry |
| `U6-N-ESP-FULL-SUCCESS` | ESP_UNPROVEN で ACCEPT 条件不成立 / REJECT STORAGE only |
| `U6-N-ESP-ACCEPT-ZERO` | ESP unproven で ACCEPT TX バイト 0 |
| `U6-N-TTL-GC-PAYLOAD` | timer で payload delete → **不合格** |
| `U6-N-UNSOLICITED-ACCEPT` | recovery 後 OFFER 無し ACCEPT → 不合格 |
| `U6-G-LOWER-ATTEMPT-NO-MUT` | held attempt=5, OFFER attempt=3 same digest → mutation 0 + ACCEPT |
| `U6-G-EQUAL-ATTEMPT-DUP` | equal attempt exact dup → mutation 0 |
| `U6-G-HIGHER-ATTEMPT-FULL` | higher attempt → FULL max update then ACCEPT |
| `U6-G-CLOCK-EPOCH-CHANGE` | reboot new clock_epoch; custody held; no TTL drop |
| `U6-N-ESP-READBACK-NO-PROMOTE` | ESP UNKNOWN + readback match → still no ACCEPT |
| `U6-N-MEMORY-SPOOL-OWNERSHIP` | memory-only sender spool claims complete → 不合格 |
| `U6-N-PEER-MONO-COMPARE` | receiver uses sender_deadline vs local mono to drop → 不合格 |
| `U6-N-MAGIC-NCTC1-5BYTE` | 5-byte magic encoder → reject |
| `U6-G-SINGLE-NS-CTL` | only `ninlil.ctl.v1` used for ARW+custody; no per-kind namespace |
| `U6-N-EXTRA-NS` | open 5th kind-namespace → noncompliant |
| `U6-G-SINGLE-COMMIT-SLOT` | 2 concurrent FULL → second WOULD_BLOCK/BUSY deterministic |
| `U6-G-HANDOFF-ATOMIC` | NCH1+NCT1 handoff_complete same FULL |
| `U6-G-DISCARD-NCD1` | NCD1 atomic discard |
| `U6-G-DISCARD-CANONICAL-NCD1-NCT0` | single FULL: NCD1+delete NCT1+NCT0 |
| `U6-N-DISCARD-EMPTY-NCT1-ALT` | empty NCT1 without NCT0 → noncompliant |
| `U6-G-NCT0-LAYOUT-64` | NCT0 end=64 CRC[0..60) |
| `U6-G-NCP-TERMINAL-SAME-FULL` | terminal state+payload policy same FULL |
| `U6-G-NCP-PAYLOAD-PRESENT` | REL_IMMEDIATE: payload_present=0 digest immutable |
| `U6-N-NCP-EMPTY-DIGEST-REWRITE` | terminal rewrites content_digest to empty → noncompliant |
| `U6-G-NCD1-ANCHOR-108` | NCD1 end=108 anchor fields |
| `U6-G-NCT0-ANCHOR-88` | NCT0 end=88 anchor fields |
| `U6-N-GC-CROSS-EPOCH` | auto GC when epoch mismatch → noncompliant |
| `U6-G-RETENTION-SAME-EPOCH` | elapsed only same clock_epoch_id |
| `U6-N-BUDGET-RESET-ON-BOOT` | budget reset to max on boot → fail |
| `U6-G-KEY-ARW-36` | ARW key 36B with recipient |
| `U6-N-MIXED-HANDOFF-UNKNOWN` | NCH1 new NCT1 old → CORRUPT |
| `U6-G-HIGHER-ATTEMPT-READBACK-BIND` | UNKNOWN readback full bind |
| `U6-N-U64-EPOCH-TRUNC` | u64 epoch field → noncompliant |
| `U6-N-OFFER-DEADLINE-FIELD` | sender_deadline field present → layout reject |
| `U6-G-ACCEPT-NOTIFIED-ORDER` | accept_notified=1 only after ACCEPT raw |
| `U6-G-NO-SPACE-TOMBSTONE` | GC only eligible tombstoned |

### 15.2 Golden wire

| ID | 内容 |
| --- | --- |
| `U6-G-WIRE-OFFER-HEX` | NCL1+NCG1 golden |
| `U6-G-WIRE-ACCEPT-HEX` | golden; body 56 end arithmetic |
| `U6-G-WIRE-REJECT-HEX` | golden; body 60 |
| `U6-G-WIRE-BUSY-HEX` | golden; body 64 |

### 15.3 ESP

| Gate | 内容 |
| --- | --- |
| compile/link | custody private sources + storage |
| runtime | **ACCEPT/R_HELD success 禁止** until B-U6-ESP-FULL 解消; OFFER→REJECT STORAGE 統一 |
| HIL | 21章 power-cut matrix 通過後にのみ success テストを有効化 |

## 16. Acceptance / evidence

| Gate | 証明 | 非証明 |
| --- | --- | --- |
| host pure + SQLite crash matrix | dual FULL / UNKNOWN / duplicate / fence / boot / no TTL GC | 実 USB / ESP FULL |
| vector bridge | codec bytes | HIL |
| ESP compile | build | custody success |
| ESP HIL after attestation | FULL custody success 候補 | series complete / Receipt |

## 17. Blockers

| ID | 条件 | ブロック |
| --- | --- | --- |
| **B-U6-ESP-FULL** | 21章 power-cut HIL PASS + FULL attestation 無し | ESP 上 custody success / ACCEPT / field Cell spool complete |
| **B-U6-U4-SESSION** | U4 session 未実装 | 実 USB session 統合（host fake session 上の pure は可） |
| **B-U6-STORAGE-PORT** | FULL を契約どおり返せない port | その port 上の U6 complete |

Open/TBD/TODO は残さない。fragmentation が必要になった場合は **新 control_version または新章**でだけ追加し、本章 single-frame 契約を silent 拡張しない。

## 18. Integration status（R2 Normative 正本 + 本 branch rebase 済み）

**成立済み:** docs/24 + ADR-0004 は main 統合済み R2 Normative 正本。本 U5/U6 branch は origin/main へ **rebase 済み**。U5 term/digest/`permit_bind_generation` fence と docs/05・23 は **docs 整合済み**。本 U6（docs/26）は番号衝突なし。
**未完（非主張）:** R2 runtime / HIL / legal / RF、U5/U6 runtime complete。
**独立再レビュー合格まで U6 GO / complete 主張禁止。**
実装 Required gate: `tools/u5_u6_docs_gate.py check` + `self-test`（immutability/freshness pin; NLP ではない）。

## 19. Acceptance checklist（本 docs freeze）

- [x] stable transfer id + attempt/digest/length bind
- [x] OFFER/ACCEPT/REJECT/BUSY exact wire
- [x] receiver FULL atomic group; sender evidence FULL; release policy
- [x] **receiver** custody 終了 = handoff/discard のみ（R_HELD TTL delete **禁止**）; sender payload 解放 = §14.1 `custody_payload_release`（REL_HOLD は auto GC **禁止**）
- [x] boot recovery exact algorithm; re-OFFER 待ち re-ACCEPT; unsolicited ACCEPT 禁止
- [x] duplicate/conflict/ACK loss/reconnect/retry; COMMIT_UNKNOWN 両 truth
- [x] ESP unproven: ACCEPT 禁止 + REJECT STORAGE 統一
- [x] bounded entries+bytes/overflow/backpressure
- [x] Application Receipt 分離; raw CDC/NCG1/ACK ≠ success
- [x] symmetric bidirectional; single-frame ≤926; fragmentation 非主張
- [x] host pure/SQLite crash; ESP success 禁止 until HIL
- [x] exact states/transitions/linearization/recovery/limits/vectors
- [x] blockers 明示; Open/TBD なし
- [x] durable NCT1/NCP1/NCS1/NCH1 exact magic/CRC/key; S_RECOVER_QUERY 廃止
- [x] single namespace `ninlil.ctl.v1` shared with U5 ARW; ESP ns budget
- [x] clock_epoch; peer mono 比較禁止; attempt lower/equal/higher closed
- [x] single global RW commit slot; ESP readback 非昇格; FULL sender spool
- [x] u5_u6_docs_gate Required; 独立再レビューまで GO 禁止
