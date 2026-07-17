# 25. U5: CellOperatingAssignment（control protocol v2）

状態: **Normative freeze（docs only; 実装未着手）**<br>
対象: Controller↔Cell Agent USB control 上の **mutable CellOperatingAssignment** と **negotiated control protocol v2** catalog<br>
依存: [ADR-0005](adr/0005-u5-cell-operating-assignment-control-v2.md)（Accepted）、[23章](23-usb-radio-boundary.md) U0–U4、[19章](19-m3-control-byte-stream-framing.md) NCG1、[22章](22-m3-owner-cell-agent-skeleton.md) Cell skeleton<br>
関連: [03](03-identity-and-join.md), [04](04-runtime-api-and-storage.md), [05](05-security-and-compliance.md), [06](06-versioning-and-compatibility.md), [07](07-testing-and-quality.md), [09](09-roadmap.md), [21](21-m3-esp-idf-durable-storage.md), [ADR-0003](adr/0003-radio-usb-dependency-direction.md), [ADR-0006](adr/0006-u6-transport-custody.md)

## 1. 位置付けと非主張

本章は USB series **U5** の **唯一の Normative 正本**である。コード実装・public ABI 変更・commit は本章の範囲外（本 freeze 時点）。

| 層 | 本章で固定するか | 状態 |
| --- | --- | --- |
| NCL1 envelope v1（magic/header/MAX） | **維持**（再定義しない; [23章 §7](23-usb-radio-boundary.md)） | Normative private |
| control protocol **v1** closed catalog | **変更しない**（HELLO/PING/PONG/RESET/CTRL_ERROR） | Normative private |
| control protocol **v2** assignment catalog | **する（exact）** | Normative private |
| RuntimeRole / logical link role / CellOperatingAssignment 分離 | **する** | Normative |
| authority proof 境界（LAB_ONLY / EXTERNAL_VERIFIED） | **する** | Normative |
| volatile session-bound assignment | **する** | Normative |
| Site Membership / Attachment / Route Lease 本線 | **しない** | M4 以降 |
| Physical Compliance Permit 実装 / SX1262 | **しない** | R-series / M5 |
| cryptographic suite の byte 固定 | **しない**（proof kind 境界のみ） | M4–M5 provider |
| durable last-known-good **assignment body**（RF 用 LKG） | **主張しない** | 非対象 |
| durable **anti-replay watermark**（precedence floor のみ） | **する**（§7.6; body/LKG ではない） | Normative |
| public C ABI / installed header | **しない** | 別 ADR |
| U5 complete / USB series complete / M3–M5 complete | **主張しない** | 実装+Required HIL 後 |

**Forbidden claims（MUST NOT assert）:**

- USB Control HELLO 成功 = Site Membership / Attachment / FIELD RF 許可
- ASSIGNMENT_ACK 成功 = Physical Compliance Permit 発行可能（proof/environment 条件を満たさない場合）
- assignment wire 成功 = Application Receipt / Transport Custody 成功
- compile success = HIL PASS
- 永続 LKG assignment により session 失効後も RF 継続
- control protocol v1 peer への silent v2 type 送信
- NCL1 `logical_version=1` closed catalog への silent type 追加
- KGuard 固有 schema / policy が portable Core / private control 必須語彙であること

## 2. Version domain と control protocol v2

### 2.1 Domain 分離（[06章](06-versioning-and-compatibility.md) / [23章 §7.1](23-usb-radio-boundary.md)）

| Domain | 識別 | U5 規範 |
| --- | --- | --- |
| NCG1 frame format | docs/19 `version` | exact 1 |
| NCL1 envelope format | header `logical_version` | **exact 1**（本章は変更しない） |
| Negotiated control protocol | HELLO `min/max/selected_control_version` | **v1 または v2**。assignment は **selected_control_version exact 2** のみ（`>=2` / future v3 silent 互換 **禁止**） |
| Public C ABI | `include/ninlil` | 変更なし |
| Secure radio wire | unallocated | 非対象 |

規則:

1. NCL1 `logical_version != 1` → 従来どおり reject（negotiate しない）。
2. control protocol version 交差が空 → `HELLO_VERSION_MISMATCH`。
3. `selected_control_version == 1` の session で v2 `message_type` を受信 → **reject** + `ncl1_reject_unknown_message_type` または `ncl1_reject_control_version` + 業務解釈しない。
4. **v2 assignment catalog を解釈・送出してよいのは `selected_control_version == 2` のときだけ**。`>= 2` 解釈・`>2` を v2 として silent 許可することは **禁止**（future v3 は別 Normative freeze）。
5. **v1 closed catalog に type を追加してはならない。** v2 追加は本章と ADR-0005 の同一変更でだけ行う。

### 2.2 HELLO 交渉（v2 exact）

HELLO / HELLO_ACK body layout は [23章 §8.4](23-usb-radio-boundary.md) を維持する（各 8 bytes）。

| 項目 | 規範 |
| --- | --- |
| U4-only peer | `min=max=1` を送受信。従来 golden を壊さない |
| U5-capable peer | `min_control_version ∈ {1,2}`、`max_control_version ∈ {1,2}`、`min ≤ max` |
| 交差選択 | `selected = max( intersection(local[min,max], peer[min,max]) )`。空なら VERSION_MISMATCH |
| U5 機能使用条件 | 双方が 2 を support し `selected_control_version == 2` |
| flags_supported / flags_selected | U5 でも **exact 0**（将来 flag は別 freeze; 非 0 は reject） |
| reserved | exact 0 |

**実装規則:** Controller が assignment を送る前に `SESSION_ACTIVE` かつ `selected_control_version == 2` を確認する。満たさなければ local `ERR_VERSION` / 送出せず。

### 2.3 NCG1 type binding（v2 message）

全 U5 assignment message は NCG1 type **`DATA` (0x03)** のみ。PING/PONG/RESET NCG1 type に載せてはならない。

| NCL1 message_type | NCG1 type | 違反時 |
| --- | --- | --- |
| `ASSIGNMENT_SET` 0x20 | DATA 0x03 only | reject + `ncl1_reject_type_binding` |
| `ASSIGNMENT_ACK` 0x21 | DATA 0x03 only | 同上 |
| `ASSIGNMENT_REJECT` 0x22 | DATA 0x03 only | 同上 |

## 3. 三層 role 分離（Normative）

### 3.1 定義

| 用語 | 定義 | 固定点 | 変更手段 |
| --- | --- | --- | --- |
| **RuntimeRole** | [04章](04-runtime-api-and-storage.md) の CONTROLLER / CELL_AGENT / ENDPOINT | `runtime_create` | Runtime 再作成のみ |
| **Logical link role** | USB control session 上の **Controller**（HELLO sole initiator）または **Cell**（HELLO responder） | HELLO 成功時に確立 | 新 session / re-HELLO |
| **CellOperatingAssignment** | Cell の **運用割当文書**: recipient device、site、assignment identity/revision/epoch、controller identity/term、cell_id、channel、operating_role、capability、digest、authority proof | **当該 control session の volatile active slot** | `ASSIGNMENT_SET` 受理+適用 |

**MUST NOT:**

1. RuntimeRole を wire の `operating_role` と同一値空間にする。
2. logical link role を Site Membership / Attachment 成功とみなす。
3. CellOperatingAssignment を Device Identity の書き換えとみなす。
4. FreeRTOS Owner Task Join ACK（[22章](22-m3-owner-cell-agent-skeleton.md) / [23章 §11](23-usb-radio-boundary.md)）を assignment 成功とみなす。

### 3.2 Logical link role × assignment 送信権限

| message | Controller TX | Cell TX |
| --- | --- | --- |
| `ASSIGNMENT_SET` | **のみ** | ✗ |
| `ASSIGNMENT_ACK` | ✗ | **のみ** |
| `ASSIGNMENT_REJECT` | ✗ | **のみ** |

逆送 → reject + `assignment_reject_invalid_role` + 状態不変。

## 4. CellOperatingAssignment 文書モデル

### 4.1 概念 field（適用後 active 観測）

| Field | 型（論理） | 意味 |
| --- | --- | --- |
| `recipient_device_id` | 16-byte opaque | 割当対象 Device Identity（stable） |
| `site_domain_id` | 16-byte opaque | Site / management domain |
| `assignment_identity` | 16-byte opaque | SiteAssignment / operating assignment 文書 identity |
| `assignment_revision` | u32 | 文書 revision（同一 identity 内単調; wrap 禁止運用） |
| `assignment_epoch` | u32 | assignment epoch（[03章](03-identity-and-join.md) fencing） |
| `controller_identity` | 16-byte opaque | 発行 Controller の stable identity |
| `controller_term` | u64 | active Controller writer term（[01章](01-architecture.md)） |
| `cell_id` | u32 | logical cell locator（0 禁止 when applied） |
| `channel_id` | u16 | radio / control channel index（profile 解釈; 0 は「未割当 channel」禁止 — applied では ≥1 または profile 定義の valid set） |
| `operating_role` | u8 closed | §4.2 |
| `capability_bits` | u32 | §4.3 |
| `assignment_digest` | 32-byte | §4.4 canonical digest |
| `authority_proof_kind` | u8 closed | §5 |
| `authority_proof` | opaque 0..256 B | kind に従う |

Physical Compliance Permit への SiteAssignment 系 bind（[23章 §9](23-usb-radio-boundary.md) / [05章](05-security-and-compliance.md) `NIN-CMP-001` / R2）は、active CellOperatingAssignment から次を **すべて**供給する（別名の第二文書を発明しない）:

| Permit bind 項目 | active assignment field |
| --- | --- |
| SiteAssignment identity | `assignment_identity` |
| SiteAssignment revision | `assignment_revision` |
| SiteAssignment epoch | `assignment_epoch` |
| **controller_term**（U5 拡張; MUST） | `controller_term` |
| **assignment_digest**（U5 拡張; MUST） | `assignment_digest` |

**outstanding Physical Permit fence（MUST; 偽 consume 禁止）:**

次の **いずれか**が変わる apply（first apply 含む identity 交代、same identity/revision/epoch でも term/digest 等の mutation を含む）の **同一 step** で、apply 完了前に:

1. 当該 Cell 上の **outstanding Physical Compliance Permit**（未 consume / 予約中）を **atomic fence** する（発行取消または consume 不可にする; ledger 予約は保守的に消費済み扱いでよい — [05章](05-security-and-compliance.md)）
2. 旧 bind スナップショットの permit を **consume させない**（term/digest mismatch で consume 拒否でも、**fence 省略は禁止** — race で旧 permit が残るため）
3. 新 active が確立した後にだけ、新 bind での **新 plan + 新 permit** を許可する

同一 `(identity, revision, epoch)` のまま `controller_term` または `assignment_digest` だけが変わる場合も **mutation** であり fence 必須。
**R2 正本（現状）:** `docs/24` + ADR-0004 は main 統合済みの Physical Compliance Permit Normative 正本である。本 branch は origin/main へ **rebase 済み**で、本表の term/digest/`permit_bind_generation` fence は docs/24・05・23 と **整合済み**。R2 **runtime authority 実装 / HIL / legal / RF complete は未**（docs freeze の一致のみ主張; §16）。

### 4.2 `operating_role` closed catalog

| 値 | 名前 | 意味 |
| ---: | --- | --- |
| `0x00` | `OP_ROLE_RESERVED` | wire 禁止（reject） |
| `0x01` | `OP_ROLE_USB_CONTROL_ONLY` | USB control のみ。physical RF TX を自ら起動しない |
| `0x02` | `OP_ROLE_RADIO_PARENT` | radio parent / cell radio 責務（Permit 経路が別途成立する場合のみ TX） |
| `0x03` | `OP_ROLE_USB_AND_RADIO` | USB control + radio parent |
| `0x04`..`0xFE` | — | **reject**（未知 critical） |
| `0xFF` | — | **reject** |

### 4.3 `capability_bits`（bit flags; unknown bit fail-closed）

| Bit | 名前 | 意味 |
| ---: | --- | --- |
| 0 | `CAP_CONTROL_SESSION` | control session 維持（U5 では applied 時 **必須 1**） |
| 1 | `CAP_RADIO_TX_CANDIDATE` | physical RF TX 候補（Permit は別途） |
| 2 | `CAP_RADIO_RX` | physical RF RX 候補 |
| 3 | `CAP_CUSTODY_ENDPOINT` | U6 custody 端点として参加可 |
| 4..31 | reserved | **must be 0**。非 0 → reject `ASSIGN_REJECT_CAPABILITY` |

`operating_role` と矛盾する capability は reject:

| operating_role | 必須 | 禁止 |
| --- | --- | --- |
| `USB_CONTROL_ONLY` | bit0=1 | bit1=0 必須 |
| `RADIO_PARENT` | bit0=1, bit1=1, bit2=1 | — |
| `USB_AND_RADIO` | bit0=1, bit1=1, bit2=1 | — |

### 4.4 Canonical `assignment_digest`（SHA-256）

digest 入力は **wire body offset 0..91 の exact 92 bytes**（§6.2; proof および digest フィールド自身を除く）。SHA-256 → 32 bytes を body offset 92 に格納する。

規則:

1. digest は **送信前に Controller が計算**し body に載せる。
2. Cell は受信 body から **独立再計算**し、wire 上 digest と bit-exact 一致しなければ reject `ASSIGN_REJECT_DIGEST`。
3. digest は authority proof の署名対象（EXTERNAL_VERIFIED）にもなる（§5）。
4. C struct memory image / host endian を digest 入力にしてはならない。

## 5. Authority proof 境界

### 5.1 Environment との関係（[05章](05-security-and-compliance.md)）

| Runtime environment | 受理可能な `authority_proof_kind` | active assignment を Physical Compliance Permit の SiteAssignment 入力に使えるか |
| --- | --- | --- |
| `TEST` | `AUTHORITY_NONE` のみ | **否**（physical RF なし / loopback のみ） |
| `LAB` | `AUTHORITY_NONE` または `AUTHORITY_EXTERNAL_VERIFIED` | **LAB_ONLY** RegulatoryProfile に限り **条件付き可**（§5.3） |
| `FIELD_PILOT` | **`AUTHORITY_EXTERNAL_VERIFIED` のみ** | proof 検証成功時のみ |
| `PRODUCTION` | **`AUTHORITY_EXTERNAL_VERIFIED` のみ** | proof 検証成功時のみ |
| unknown | — | 起動拒否（05章）— assignment 以前 |

### 5.2 `authority_proof_kind` closed catalog

| 値 | 名前 | proof bytes | 意味 |
| ---: | --- | --- | --- |
| `0x00` | `AUTHORITY_NONE` | length **exact 0** | LAB/TEST のみ。**FIELD では active Permit 入力禁止** |
| `0x01` | `AUTHORITY_EXTERNAL_VERIFIED` | length **1..256** | 外部検証済 authority の opaque proof（§5.4） |
| `0x02`..`0xFF` | — | — | **reject** |

### 5.3 LAB_ONLY 経路（exact）

1. environment が `LAB` であること。
2. `authority_proof_kind == AUTHORITY_NONE` かつ proof length 0、**または** EXTERNAL_VERIFIED で検証成功。
3. active assignment を Permit に bind する場合、RegulatoryProfile approval は **`LAB_ONLY` のみ**（`DEPLOYMENT_APPROVED` を LAB 経路で偽装しない）。
4. LAB assignment 成功を PRODUCTION / FIELD 認可と表示しない。

### 5.4 EXTERNAL_VERIFIED 経路（exact boundary; suite 非固定）

U5 は次を固定する:

| 項目 | 規範 |
| --- | --- |
| proof の意味 | `assignment_digest` および（provider が要求する）controller/site binding に対する **外部 authority の検証可能証跡** |
| 検証入口 | private `authority_verify_ops`（vtable）。portable Core に suite をハードコードしない |
| 検証失敗 | assignment **非適用** + `ASSIGNMENT_REJECT` reason `ASSIGN_REJECT_AUTHORITY` |
| 検証不能（ops 未設定） | FIELD_PILOT/PRODUCTION では **SET を受理しても active にしない** / reject AUTHORITY。LAB では AUTHORITY_NONE のみに fallback **しない**（SET が EXTERNAL を要求している場合） |
| suite / OID / key layout | **本章で固定しない** |
| **Blocker B-U5-AUTH-SUITE** | FIELD_PILOT/PRODUCTION で EXTERNAL_VERIFIED を **実装して green にする**には、M4–M5 の authority suite Normative（アルゴリズム・key ID・canonical signed bytes）が **別文書で Accepted** していること。**未解消のまま FIELD 実装完了を名乗ってはならない**（LAB + AUTHORITY_NONE 実装は本 blocker の対象外） |

### 5.5 USB HELLO 単独の禁止（再掲）

次のどれも **FIELD RF 認可を成立させない**:

- Control HELLO / `SESSION_ACTIVE`
- `ASSIGNMENT_ACK` のみ（proof/environment 不足）
- PONG liveness
- Owner Task Join ACK
- raw CDC write accept

## 6. Wire layout（exact; big-endian）

全 multi-byte は **unsigned big-endian**。C struct `memcpy` / padding 禁止。NCL1 header は [23章 §7.2](23-usb-radio-boundary.md)（26 bytes）。

### 6.1 message_type catalog（control protocol v2 only）

| message_type | 値 | body_length | 相関 | NCG1 |
| --- | ---: | ---: | --- | --- |
| `ASSIGNMENT_SET` | `0x20` | **exact 148 + proof_len**（`proof_len` = body **offset 126..127** u16 BE） | request: nonzero `request_id` | DATA |
| `ASSIGNMENT_ACK` | `0x21` | **exact 64** | response: echo `request_id` | DATA |
| `ASSIGNMENT_REJECT` | `0x22` | **exact 76** | response: echo `request_id` | DATA |

`proof_len ∈ [0, 256]`。`body_length != 148 + proof_len` → reject layout。
`148 + 256 = 404 ≤ 998`（MAX_NCL1_BODY）。

**Length 算術（必須; 実装・golden が一致）:**

| body | 合計 | 根拠 |
| --- | ---: | --- |
| SET fixed prefix | **148** | §6.2: last fixed byte = offset 147 |
| ACK | **64** | §6.3: fields end exclusive offset **64** |
| REJECT | **76** | §6.4: fields end exclusive offset **76** |

v1 catalog（0x01..0x03, 0x10..0x12）は不変。`0x20`.. は **v2 session でのみ** known。

### 6.2 `ASSIGNMENT_SET` body

各行: `offset` は inclusive 開始、`end` は exclusive、`size = end - offset`。

```text
offset  size  end   field
0       16    16    recipient_device_id
16      16    32    site_domain_id
32      16    48    assignment_identity
48      4     52    assignment_revision     u32 BE
52      4     56    assignment_epoch        u32 BE
56      16    72    controller_identity
72      8     80    controller_term         u64 BE
80      4     84    cell_id                 u32 BE; applied 時 ≠0
84      2     86    channel_id              u16 BE; applied 時 ≠0
86      1     87    operating_role          §4.2
87      1     88    reserved0               exact 0
88      4     92    capability_bits         u32 BE §4.3
92      32    124   assignment_digest       SHA-256 §4.4
124     1     125   authority_proof_kind    §5.2
125     1     126   reserved1               exact 0
126     2     128   authority_proof_length  u16 BE; 0..256
128     20    148   reserved_tail           20 bytes exact 0
148     L     148+L authority_proof         L = authority_proof_length
```

**固定 prefix = 148 bytes**（bytes `[0,148)`）。digest 入力 = body **`[0,92)` exact 92 bytes**:

```text
recipient_device_id || site_domain_id || assignment_identity ||
assignment_revision || assignment_epoch || controller_identity ||
controller_term || cell_id || channel_id || operating_role ||
reserved0(0x00) || capability_bits
= 16+16+16+4+4+16+8+4+2+1+1+4 = 92 bytes
```

`assignment_digest` は **`[92,124)`**。proof 関連は **`[124,148+L)`**。digest 入力に **含めない**。

Header 規則（SET）:

| field | 値 |
| --- | --- |
| session_generation / session_cookie | active と bit-exact（SESSION_ACTIVE のみ） |
| request_id | nonzero; inflight 登録（§7.4） |
| flags | 0 |

### 6.3 `ASSIGNMENT_ACK` body（**exact 64 bytes**; `[0,64)`）

```text
offset  size  end   field
0       8     8     controller_term         u64 BE  （受理した SET と exact）
8       4     12    assignment_epoch        u32 BE
12      4     16    assignment_revision     u32 BE
16      16    32    assignment_identity
32      32    64    assignment_digest       受理 digest exact
```

算術: `8+4+4+16+32 = 64`。**body_length は 64 のみ**（旧誤記 56 は layout reject）。

Header: active gen/cookie; `request_id` = SET の echo。

### 6.4 `ASSIGNMENT_REJECT` body（**exact 76 bytes**; `[0,76)`）

```text
offset  size  end   field
0       8     8     controller_term         u64 BE  （拒否対象 SET; 不明なら 0）
8       4     12    assignment_epoch        u32 BE
12      4     16    assignment_revision     u32 BE
16      16    32    assignment_identity
32      32    64    assignment_digest
64      2     66    reject_code             u16 BE §6.5
66      2     68    reserved0               exact 0
68      8     76    reserved1               exact 0
```

算術: `8+4+4+16+32+2+2+8 = 76`。
**禁止（旧誤記）:** `reject_code` を offset 48 に置くこと（digest `[32,64)` と **overlap**）。`body_length=60` は **reject layout**。

### 6.5 `reject_code` closed catalog

| 値 | 名前 | 意味 |
| ---: | --- | --- |
| `0x0001` | `ASSIGN_REJECT_STALE` | floor（active ∪ ARW §7.6）より term/epoch/revision が古い |
| `0x0002` | `ASSIGN_REJECT_CONFLICT` | 同一 term+epoch+revision で digest 不一致 |
| `0x0003` | `ASSIGN_REJECT_DIGEST` | digest 再計算不一致 |
| `0x0004` | `ASSIGN_REJECT_AUTHORITY` | proof 検証失敗 / FIELD で NONE |
| `0x0005` | `ASSIGN_REJECT_RECIPIENT` | recipient_device_id が local device と不一致 |
| `0x0006` | `ASSIGN_REJECT_CAPABILITY` | capability / operating_role 矛盾または reserved bit |
| `0x0007` | `ASSIGN_REJECT_STATE` | session 非 ACTIVE / control_version が 2 未満 / 適用不能状態 |
| `0x0008` | `ASSIGN_REJECT_BUSY` | inflight 飽和または local 適用中 |
| `0x0009` | `ASSIGN_REJECT_LAYOUT` | reserved / length / channel/cell 0 等 |
| `0x000A` | `ASSIGN_REJECT_SESSION` | gen/cookie mismatch（通常は NCL1 層で先に落ちる） |
| `0x000B` | `ASSIGN_REJECT_WATERMARK_STORAGE` | ARW durable FULL 不能 / COMMIT_UNKNOWN 未収束 / ESP unproven |

未知 reject_code を Controller が受けた場合: 業務適用せず counter + session 維持可。

### 6.6 Closed field zero / nonzero（SET validation; exact）

| field | 規則 | 違反 |
| --- | --- | --- |
| `recipient_device_id` | **all-zero 禁止** | REJECT RECIPIENT または LAYOUT |
| `site_domain_id` | **all-zero 禁止** | LAYOUT |
| `assignment_identity` | **all-zero 禁止** | LAYOUT |
| `controller_identity` | **all-zero 禁止** | LAYOUT |
| `assignment_revision` | **≥ 1**（0 禁止） | LAYOUT |
| `assignment_epoch` | **≥ 1**（0 禁止） | LAYOUT |
| `controller_term` | **≥ 1**（0 禁止） | LAYOUT |
| `cell_id` | **≠ 0** | LAYOUT |
| `channel_id` | **≠ 0** | LAYOUT |
| `assignment_digest` | 任意 32B（再計算一致必須） | DIGEST |
| `authority_proof_kind` | closed §5.2 | AUTHORITY/LAYOUT |
| `authority_proof_length` | 0..256; kind NONE なら **exact 0** | LAYOUT |

REJECT body で対象不明のときだけ `controller_term=0` を **echo フィールドとして**許可（§6.4）。SET では 0 禁止。

## 7. 状態機械と session 結合

### 7.1 Cell local assignment states

```text
ASSIGN_NONE
  -- SESSION_ACTIVE + control_version==2 --> ASSIGN_NONE（待機）
  -- RX valid ASSIGNMENT_SET --> evaluate §8
       * apply --> ASSIGN_ACTIVE + TX ASSIGNMENT_ACK
       * reject --> ASSIGN_NONE|ASSIGN_ACTIVE（現状維持）+ TX ASSIGNMENT_REJECT
  -- session INVALID / re-HELLO / link down --> ASSIGN_NONE
       （volatile active を破棄。LKG 非主張）

ASSIGN_ACTIVE
  -- RX SET exact duplicate (§8.3) --> stay + TX ACK（idempotent）
  -- RX SET higher precedence --> replace active + TX ACK
  -- RX SET stale --> stay + TX REJECT STALE
  -- RX SET conflict --> stay + TX REJECT CONFLICT
  -- session INVALID / re-HELLO / link down --> ASSIGN_NONE
```

Controller 側:

```text
CTRL_ASSIGN_IDLE
  -- SESSION_ACTIVE && selected==2 --> may TX SET --> CTRL_ASSIGN_INFLIGHT
CTRL_ASSIGN_INFLIGHT
  -- ACK matching --> CTRL_ASSIGN_APPLIED_REMOTE（観測; local journal 任意）
  -- REJECT matching --> CTRL_ASSIGN_IDLE（reason 記録）
  -- timeout §7.5 --> retry or fail-closed（§7.5）
  -- session fence --> CTRL_ASSIGN_IDLE; inflight 破棄
```

### 7.2 Volatile session bind（永続 LKG **body** 非主張）

| 事象 | volatile **active assignment body** | durable **ARW**（§7.6） |
| --- | --- | --- |
| 新 `SESSION_ACTIVE` | **空**から開始。旧 session の active を持ち越さない | **保持**（消さない） |
| session INVALID / RESET_SESSION / RX overflow fence 等 | **即 ASSIGN_NONE** | **保持** |
| process restart | **空**（body を RF/Permit へ silent 復元しない） | storage から **再ロード**（§7.6.4） |
| 新 session での再適用 | Controller が **exact SET 再送**。Cell は §8 + ARW floor で再評価 | floor により **lower term 再適用を拒否** |

**MUST NOT:** flash に残った前回 **assignment body** を、新 session で proof 再検証なしに `ASSIGN_ACTIVE` へ silent 復元して Permit に bind する。
**MUST:** ARW は **site domain floor + last identity + digest + proof_digest** を永続する。**完全 body LKG ではない**（cell/channel 等は volatile SET 再検証）。

### 7.3 新 session exact replay

1. Controller は望ましい assignment の **canonical SET body** を保持（volatile または Controller durable journal — Cell 側 LKG body とは別）。
2. 新 HELLO で `selected_control_version==2` かつ `SESSION_ACTIVE` になったら、**同一 digest の SET を新 request_id で送ってよい**（key ≥ ARW floor である必要がある）。
3. Cell は volatile active 空でも **ARW floor** と比較する（§8.1）。higher/equal-valid のみ apply。
4. replay が floor より古い → REJECT STALE（Controller が新文書を発行する責任）。

### 7.4 inflight / request_id

| 項目 | 規範 |
| --- | --- |
| SET inflight | session あたり **最大 1**（HELLO/PING の map と **共有上限 8** の内数; SET は同時 1） |
| request_id | Controller local allocator nonzero; ACK/REJECT は echo |
| 同時 2 件目 SET | 送出せず `ASSIGN_REJECT_BUSY` 相当 local / または先 SET 完了待ち |
| stale response | request_id が inflight に無い → drop + counter; state 不変 |

### 7.5 timeout / retry（monotonic）

| 項目 | 値 |
| --- | --- |
| `assignment_ack_timeout_ms` | **2000** |
| `assignment_retry_max` | **5**（同一 digest; 超過で local fail-closed + operator reason） |
| clock | **monotonic のみ**（wall clock 禁止） |
| retry | 新 `request_id`、同一 body/digest 可。NCG1 sequence は U4 規則（cold しない） |

### 7.6 Durable anti-replay watermark（ARW; site/controller domain; exact）

#### 7.6.1 目的と非対象

| 項目 | 規範 |
| --- | --- |
| 目的 | session clear / reboot 後の **term/epoch/revision rollback** を防ぐ。**assignment_identity を変えて旧 high-term floor を迂回することを禁止**する |
| 永続 domain | **`site_domain_id` 単位 1 record**（site authority domain）。key に `assignment_identity` を **含めない** |
| 永続する比較材料 | floor `(term,epoch,revision)` + `controller_identity` + **last `assignment_identity`** + **`assignment_digest`** + **`authority_proof_kind` + `authority_proof_digest`**（推測比較禁止） |
| 永続しないもの | cell_id / channel / capability / **raw proof bytes** / 完全 assignment body（= **LKG body 非主張**; RF は volatile active + §5 のみ） |
| RF | ARW 単独は Permit 入力に **使わない** |

**禁止（旧設計）:** key = `(site_domain_id, assignment_identity)`。identity 差し替えで high-term を回避できるため **U5 非準拠**。

#### 7.6.2 Storage placement（namespace budget; [26章 §11.0](26-u6-transport-custody.md) と共有）

U5 ARW と U6 custody は **同一 storage namespace** `ninlil.ctl.v1` に置く（ESP production default **2** namespaces / hard max **4** に収める; §7.6.7 / 26章）。
ARW 専用 `ninlil.u5.arw.v1` namespaceは **廃止**。

#### 7.6.3 Key / value layout（BE; CRC; exact）

**Authority scope:** durable ARW は **`(recipient_device_id, site_domain_id)` に exact 1 record**（local Cell では recipient = provisioned self id）。assignment_identity は **value のみ**（key に入れない → identity 差し替えで floor 迂回不可）。

**Canonical key 正本:** [26章 §11.1](26-u6-transport-custody.md) と **同一**（namespace `ninlil.ctl.v1`）。`ARW1` の key_bytes は **36 のみ**（20B ARW key は CORRUPT）。

**Key**（exact **36** bytes）:

```text
offset  size  end   field
0       4     4     kind_magic              exact ASCII "ARW1" = 41 52 57 31
4       16    20    site_domain_id          ≠ all-zero
20      16    36    recipient_device_id     ≠ all-zero
```

**Value**（exact **172** bytes; multi-byte **unsigned big-endian**; memcpy 禁止）:

```text
offset  size  end   field
0       4     4     magic                   exact "ARW1"
4       4     8     format_version          u32 BE = 1
8       2     10    value_length            u16 BE = exact 172
10      2     12    reserved0               exact 0
12      16    28    site_domain_id          = key[4..20)
28      16    44    recipient_device_id     = key[20..36)
44      16    60    assignment_identity     last applied; ≠0
60      8     68    controller_term         u64 BE ≥1
68      4     72    assignment_epoch        u32 BE ≥1
72      4     76    assignment_revision     u32 BE ≥1
76      16    92    controller_identity     ≠0
92      32    124   assignment_digest       §4.4 last applied
124     1     125   authority_proof_kind    §5.2
125     3     128   reserved1               exact 0
128     32    160   authority_proof_digest  SHA-256(proof bytes); len0→SHA-256("")
160     8     168   permit_bind_generation  u64 BE ≥1（§8.5）
168     4     172   value_crc32c            u32 BE; CRC32C(bytes[0..168))
```

算術: `4+4+2+2+16+16+16+8+4+4+16+32+1+3+32+8+4 = 172`。
**integrity:** `value_length≠172` / CRC / magic / format_version≠1 / key↔value site|recipient mismatch → **CORRUPT**（推測禁止）。
**boot enumeration:** namespace `ninlil.ctl.v1` を kind=`ARW1` で scan; canonical key = 上表 36B; 重複 key / 余剰 record → CORRUPT。scope あたり **exact ≤1** VALID ARW。device 合計 ARW keys **≤4**。

#### 7.6.4 Floor と identity rotation / new identity（exact）

```text
recv_key   = (controller_term, assignment_epoch, assignment_revision)
active_key = ASSIGN_ACTIVE かつ active.site==SET.site かつ active.recipient==SET.recipient なら active key else ⊥
arw_key    = ARW VALID なら stored (term,epoch,revision) else (0,0,0)
floor_key  = max(active_key, arw_key)
```

| 条件 | 結果 |
| --- | --- |
| `recv_key < floor_key` | **REJECT STALE**（新 assignment_identity でも回避不可） |
| `recv_key > floor_key` | **higher apply 候補**（identity rotation 可）→ §8.5 |
| `recv_key == floor_key` | §7.6.5（保存 field のみ） |

**identity rotation:** higher term（または higher epoch/revision）でのみ `assignment_identity` 更新可。
**equal-key identity swap:** CONFLICT。
**same term 異 controller:** CONFLICT。

#### 7.6.5 Equal-key / restore / proof / digest（保存情報のみ）

ARW VALID かつ `recv_key == floor_key` のとき、SET を **ARW value の保存 field** とだけ比較:

| 条件 | 結果 |
| --- | --- |
| identity+controller+digest+proof_kind+SHA-256(proof)==proof_digest **すべて一致** | restore/duplicate: mutation 0; active 空なら SET body から volatile 構築可; ACK; **ARW put 不要**; permit_bind_generation **不変** |
| digest 不一致 | CONFLICT |
| digest 一致・proof_kind/proof_digest 不一致 | CONFLICT |
| digest/proof 一致・identity 不一致 | CONFLICT |
| digest/proof/identity 一致・controller 不一致 | CONFLICT |

#### 7.6.6 ESP unattested と host recovery の優先（U6 と同一）

| media | FULL 結果 | read-back 一致時 |
| --- | --- | --- |
| host FULL 証明 port | `STORAGE_OK` | recovery で active 構築 + ACK 可（§7.6.8） |
| host FULL 証明 port | `COMMIT_UNKNOWN` | read-back **full value bit-exact 一致**なら 3a として ACK 可 |
| **ESP unattested** | 常に UNKNOWN または FULL 拒否 | **read-back 一致でも active 更新 / ACK / FIELD apply 昇格 禁止**（U6 §9.4 と同優先） |

#### 7.6.7 Namespace / handles / capacity

| 項目 | 規範 |
| --- | --- |
| namespace | **`ninlil.ctl.v1`**（U6 と共有） |
| ARW keys max | **4** scopes |
| RW/RO/iter | control 全体 **RW≤1 RO≤1 iter≤1** |
| max keys ns | **32** |

#### 7.6.8 COMMIT_UNKNOWN / recovery（ARW FULL）

1. volatile を fence（active を推測更新しない）
2. read ARW key
3a. **host only:** value == expected_new_value（CRC 込み bit-exact）→ active を SET から構築可 → ACK
3b. 旧 value / 不在 → 未 commit; 再 SET
3c. CORRUPT → fail-closed
3d. **ESP unattested: 3a を適用しない**（一致しても success 禁止）

#### 7.6.9 Environment

| media | ARW FULL OK | apply/ACK | FIELD |
| --- | --- | --- | --- |
| host FULL port | 必須 | OK | §5+ARW |
| ESP unattested | 不能 | **禁止**（read-back 含む） | **禁止** |
| ESP HIL+attest | 昇格後 | 許可候補 | §5 |

**B-U5-ARW-FULL** 維持。

## 8. Precedence・duplicate・linearization

### 8.1 Precedence key（高い方が勝つ）

比較は辞書式 **降順**（大きい値が優先）:

```text
(controller_term, assignment_epoch, assignment_revision)
```

1. `controller_term` 大 → 勝つ
2. 同 term で `assignment_epoch` 大 → 勝つ
3. 同 term+epoch で `assignment_revision` 大 → 勝つ
4. 三者同一 → digest 比較へ（§8.2–8.3）

**Floor:** §7.6.4 の `floor_key = max(active_key, arw_key)` と比較する。**active だけ**を見て stale 判定してはならない。

`controller_identity` が（active または ARW の）記録と異なり **かつ** term が **strictly greater** の SET は **受理候補**（fencing 交代）。term が小さい異 identity は STALE。

**同一 term で controller_identity が異なる SET:** `ASSIGN_REJECT_CONFLICT`（split-brain; 人間/上位 reconcile。自動上書き禁止）。ARW 上の identity とも照合する。

### 8.2 Conflict

equal-key（`recv_key == floor_key`）時の conflict は **§7.6.5 が正本**（ARW 保存の digest / proof_digest / identity / controller と比較。推測禁止）。

| 代表条件 | 動作 |
| --- | --- |
| equal-key + digest 不一致 | REJECT CONFLICT |
| equal-key + digest 一致 + proof_kind/proof_digest 不一致 | REJECT CONFLICT |
| equal-key + identity 不一致 | REJECT CONFLICT |
| `recv_key < floor_key`（identity 変更を含む） | REJECT STALE（§7.6.4） |

### 8.3 Exact duplicate / restore

**正本は §7.6.5。**
volatile active があり SET が active と **body 全 field bit-exact**（proof 含む）なら ACK + mutation 0（ARW put 不要）。
active 空なら ARW 保存 digest/proof_digest/identity/controller と SET を比較し、§7.6.5 の restore 行のみ ACK。

### 8.4 Stale

受信 key が **`floor_key` より strictly smaller** → REJECT STALE。active/ARW 不変。
**reconnect 後 active 空でも ARW により STALE が成立しなければならない。**

### 8.5 ACK linearization + permit fence（exact; 短縮・入替禁止）

Cell が SET を受けた **同一 owner step** の唯一順序。

**Sole Normative authority（順序）:** 本節 algorithm の closed text fence block 内にある
machine-readable 宣言（`L6_ORDER` / `DEFERRED_FENCE_FORBIDDEN` / `L6_CONSTRAINT`）と
L0–L9・L6a–L6d 手順だけが fence/commit 順序の **唯一の Normative authority** である。
block 外の自由文・表・補足は authority ではなく、順序の override / 例外化を **主張できない**。
**Gate authority:** `tools/u5_u6_docs_gate.py` は **review 済 Normative bytes の immutability / freshness pin**
（`spec/frozen/u5-u6-normative-freeze-v1.json` + gate 内 freeze digest pin）であり、
自然言語セマンティック / NLP 分類による安全性証明ではない。人間レビューの代替を主張しない。
正当な freeze 変更は **新 version + Accepted ADR + 独立再レビュー + gate pin 更新** が必要。

```text
L0  NCL1 validation + selected_control_version==2 + role matrix
L1  layout / reserved / body_length=148+L / digest recompute / zero-nonzero §6.6
L2  recipient / capability / authority §5
L3  floor / duplicate / conflict §7.6–§8.4
L4  decision:
      REJECT_*  → enqueue REJECT; **stop**（storage mutation 0; permit 不変）
      RESTORE/DUP §7.6.5 → enqueue ACK; **stop**（ARW/permit_generation 不変; active 必要なら SET から構築）
      HIGHER_APPLY → continue L5
L5  permit fence candidate: new_permit_bind_generation = arw.permit_bind_generation+1
      （ARW 不在 first apply なら generation=1）
L6  **FULL atomic group**（single RW slot; 1 storage txn; **下位 bullet の相対順は固定**）:
      # Sole Normative machine-readable order (unique in chapter; free prose MUST NOT override):
      L6_ORDER=FENCE_BEFORE_COMMIT; DEFERRED_FENCE_FORBIDDEN=1
      L6a encode ARW value（新 floor fields + digest + proof_digest + permit_bind_generation）
      L6b **permit_fence_before_commit:** outstanding Physical Compliance Permit を
          generation < new で revoke/fence（in-memory registry clear; durable generation は ARW に bind;
          旧 generation の consume 拒否）
      L6c put ARW key（36B canonical）
      L6d commit(FULL)
      # Closed constraints (inside algorithm block only; not free-prose exceptions):
      L6_CONSTRAINT: FENCE_STEP=L6b; COMMIT_STEP=L6d; FENCE_BEFORE_COMMIT=1; SAME_OWNER_SYNC=1
      L6_CONSTRAINT: DEFERRED_AFTER_COMMIT_OR_PERSIST_FORBIDDEN=1
L7  commit 結果:
      STORAGE_OK → L8
      COMMIT_UNKNOWN → **active 非公開; ACK 禁止; permit 新 generation 未公開**
                      → §7.6.8 recovery（ESP は success 禁止）
                      → reentry: 同一 SET 再処理または Controller retry
      definite fail → REJECT WATERMARK_STORAGE; active/permit 旧状態
L8  **active publish**（volatile ASSIGN_ACTIVE = SET fields; Permit 入力可）
L9  enqueue ASSIGNMENT_ACK
```

**Physical Permit bind** は identity/revision/epoch/term/digest に加え **`permit_bind_generation`**（ARW 値）を含む（[23章](23-usb-radio-boundary.md) / [05章](05-security-and-compliance.md)）。
consume 時 live generation 不一致 → 拒否。

| 失敗点 | active | ARW | outstanding old permits | ACK |
| --- | --- | --- | --- | --- |
| L0–L4 reject | 不変 | 不変 | 不変 | REJECT or none |
| L6 UNKNOWN | 非公開 | 両 truth recovery | 旧 fence 未確定→保守的に旧も新も consume 拒否まで recovery | **禁止** |
| L6 fail | 不変 | 不変 | 不変 | REJECT STORAGE |
| L8–L9 after OK | 新 | 新 | 旧 fenced | ACK |

**MUST NOT:** L6 前に ACK。**MUST NOT:** ARW 成功前に active 公開。**MUST NOT:** permit fence 省略で旧 permit が 1 step でも consume 可能。
**reentry:** L6 UNKNOWN 中に別 SET が来たら floor は durable 再読後にのみ評価（推測 active 禁止）。

## 9. Private API / ownership 境界

### 9.1 U4 接続

| 項目 | 規範 |
| --- | --- |
| handoff | C3→L1 **typed bounded copy-out**（[23章 §4.3](23-usb-radio-boundary.md) mode (b) と整合）。summary-only pointer 禁止 |
| drive | **sole:** owner `step` / C4 `pump` からのみ assignment reducer を進める |
| TX full | `WOULD_BLOCK`; busy-spin 禁止 |
| 入力 lifetime | API 引数 pointer は call 中のみ。受理時に private storage へ **copy-in** |
| 出力 | caller buffer へ **copy-out**。library 内部 pointer を call 後に公開しない |
| public ABI | `include/ninlil/*` に出さない |

### 9.2 容量（U5 profile default）

| 資源 | 上限 |
| --- | ---: |
| active assignment slots / Cell | **1** |
| SET inflight / session | **1** |
| assignment TX intent bytes | 既存 logical TX pool 内（[23章 §4.4](23-usb-radio-boundary.md) 8192 shared） |
| proof max | **256** bytes |

## 10. Physical RF / Permit 接続（非実装; 契約; R2 整合）

1. `ASSIGN_ACTIVE` かつ §5 で Permit 入力可のときだけ、§4.1 の **全 Permit bind 項目**（identity/revision/epoch/**controller_term**/**assignment_digest**）を P1 へ供給してよい。
2. `OP_ROLE_USB_CONTROL_ONLY` または `CAP_RADIO_TX_CANDIDATE=0` のとき physical TX path を起動しない。
3. assignment 失効（ASSIGN_NONE）後、旧 bind の Permit を **発行・consume してはならない**。
4. **replacement / mutation apply**（§4.1 fence）: 旧 outstanding permit を **atomic fence** してから新 active を公開する。fence 前に旧 permit が consume 可能である状態を **1 step でも作ってはならない**。
5. consume 時: live active の term/digest/identity/revision/epoch が permit スナップショットと 1 項目でも不一致 → **consume 拒否**（[23章 §9.3](23-usb-radio-boundary.md) / [05章](05-security-and-compliance.md)）。
6. 本章は R2 Permit object の **runtime 実装本体を要求しない**。bind 表と fence 契約は docs/24 + ADR-0004（R2 Normative 正本; main 統合済み）と **本 rebase で整合済み**。矛盾する短絡を禁止する。R2 runtime / HIL / legal / RF complete は **主張しない**。

## 11. Validation order（SET; exact）

[23章 §8.1](23-usb-radio-boundary.md) steps 1–7 の後:

8. `selected_control_version == 2`（`>2` / `>=2` 解釈禁止; v3 は別 freeze）
9. message_type ∈ {0x20,0x21,0x22} と role matrix
10. body_length / reserved / cell_id≠0 / channel_id≠0 / operating_role / capability
11. digest 再計算
12. recipient_device_id == local provisioned device id（未 provision なら REJECT RECIPIENT）
13. authority §5
14. precedence + ARW floor §7.6 / §8
15. apply + ARW FULL + ACK/REJECT linearization §8.5

## 12. Structured counters（追加最小集合）

| counter | 意味 |
| --- | --- |
| `assignment_set_rx` | SET 受理（layout OK まで） |
| `assignment_applied` | active 置換または first apply |
| `assignment_duplicate_ack` | exact duplicate ACK |
| `assignment_reject_stale` | STALE |
| `assignment_reject_conflict` | CONFLICT |
| `assignment_reject_authority` | AUTHORITY |
| `assignment_reject_watermark_storage` | ARW FULL 不能 |
| `assignment_arw_advanced` | ARW value 更新成功 |
| `assignment_reject_other` | その他 reject |
| `assignment_invalid_role` | 逆送 |
| `assignment_session_cleared` | session fence で active 破棄（ARW は消さない） |
| `assignment_ack_timeout` | Controller timeout |
| `ncl1_reject_control_version` | v1 session へ v2 type |

既存 §8.10 counters を reset しない。HELLO 成功で本集合を zero にしない。

## 13. Vector set（Required at U5 implementation）

Format: independent generator + production C bridge（U4 `ncl1-u4-v1` と同型）。
ID は **安定**。実装 PR で JSON golden を追加する。

### 13.1 Golden / behavioral

| ID | 内容 |
| --- | --- |
| `U5-G-HELLO-V2-SELECT` | 双方 max≥2 → selected=2 |
| `U5-G-SET-ACK-LAB-NONE` | LAB + AUTHORITY_NONE → apply + ACK |
| `U5-G-SET-ACK-EXTERNAL` | EXTERNAL_VERIFIED mock ops success → apply + ACK |
| `U5-G-DUP-IDEMPOTENT` | exact duplicate → mutation 0 + ACK |
| `U5-G-HIGHER-TERM` | 高 term で replace + ACK |
| `U5-G-HIGHER-EPOCH` | 同 term 高 epoch replace |
| `U5-G-HIGHER-REVISION` | 同 term+epoch 高 revision replace |
| `U5-G-SESSION-CLEAR-REPLAY` | session fence → ASSIGN_NONE → 新 session exact replay apply（key ≥ ARW） |
| `U5-G-ACK-AFTER-APPLY` | linearization: ARW FULL + apply 後にのみ ACK bytes |
| `U5-G-NCG1-NCL1-ROUNDTRIP` | full NCG1+NCL1 encode/decode golden bytes |
| `U5-G-ACK-BODY-64` | ACK body_length **exact 64**; field end=64 golden |
| `U5-G-REJECT-BODY-76` | REJECT body_length **exact 76**; reject_code @64 golden |
| `U5-G-ARW-RECONNECT-STALE` | apply term=5 → session clear → SET term=3 → STALE; ARW 不変 |
| `U5-G-ARW-REBOOT-STALE` | apply → full reinit storage reload ARW → lower SET STALE |
| `U5-G-ARW-EQUAL-DIGEST-RESTORE` | active 空 + ARW equal + same digest SET → active 復元 + ACK; ARW put 0 |
| `U5-G-PERMIT-FENCE-ON-TERM` | same identity/rev/epoch + higher term → old permit fenced before ACK; spy consume old=0 |
| `U5-G-PERMIT-BIND-DIGEST` | permit snapshot includes assignment_digest+controller_term; mismatch consume deny |
| `U5-G-RESTART-STALE-AFTER-ARW` | reboot + lower SET → STALE（ARW） |
| `U5-G-ARW-IDENTITY-ROTATION-HIGHER` | higher term + new assignment_identity → apply + ARW update |
| `U5-N-ARW-IDENTITY-BYPASS` | lower term + **new** assignment_identity → STALE（旧 high floor 回避失敗） |
| `U5-G-ARW-RESTORE-DIGEST-PROOF` | equal-key + matching ARW digest/proof_digest → restore ACK |

### 13.2 Negative / mutation

| ID | 内容 |
| --- | --- |
| `U5-N-V1-SESSION-SET` | selected=1 で SET → reject; state 不変 |
| `U5-N-STALE-TERM` | 低 term → REJECT STALE |
| `U5-N-CONFLICT-DIGEST` | 同一 key 異 digest → CONFLICT |
| `U5-N-BAD-DIGEST` | wire digest 改変 → DIGEST |
| `U5-N-FIELD-NONE-AUTHORITY` | FIELD + AUTHORITY_NONE → AUTHORITY; Permit 入力不可 |
| `U5-N-HELLO-NOT-RF` | SESSION_ACTIVE のみで Permit spy TX=0 |
| `U5-N-RESERVED-NONZERO` | reserved 改変 reject |
| `U5-N-PROOF-LEN` | proof_len と body 不一致 |
| `U5-N-ROLE-REVERSE` | Cell→Controller SET reject |
| `U5-N-TYPE-BIND-SET-IN-PING` | NCG1 PING に SET |
| `U5-N-CAP-USB-WITH-TX` | USB_CONTROL_ONLY かつ CAP_RADIO_TX |
| `U5-N-CELL-ZERO` | cell_id=0 reject |
| `U5-N-POINTER-BORROW` | API 後 use-after-copy 禁止の model test |
| `U5-N-WOULD-BLOCK` | TX full で SET 未消費; 再 step |
| `U5-N-ACK-LEN-56` | ACK body_length=56（旧誤記）→ layout reject |
| `U5-N-REJECT-LEN-60` | REJECT body_length=60 → layout reject |
| `U5-N-REJECT-CODE-OVERLAP-48` | reject_code を offset 48 に置く encoder → 非準拠 / decode reject |
| `U5-N-ARW-SKIP-VOLATILE-ONLY` | ARW 無しで reconnect 後 lower を accept → **不合格** |
| `U5-N-FIELD-ARW-ESP-UNPROVEN` | ESP unproven FULL で FIELD apply/ACK → 禁止 |
| `U5-N-ACK-BEFORE-ARW` | ARW commit 前 ACK → 不合格 linearization |
| `U5-N-ACK-BEFORE-PERMIT-FENCE` | permit fence 前 ACK → 不合格 |
| `U5-N-ESP-ARW-READBACK-PROMOTE` | ESP UNKNOWN+readback で ACK/active → 不合格 |
| `U5-G-LINEARIZATION-PERMIT-ARW` | L0..L9 order host FULL |
| `U5-N-V2-GE2-SILENT` | selected=3 で SET accept → 不合格（`==2` only） |
| `U5-N-ZERO-REVISION` | assignment_revision=0 → LAYOUT |
| `U5-N-ZERO-EPOCH` | assignment_epoch=0 → LAYOUT |
| `U5-N-ZERO-TERM` | controller_term=0 on SET → LAYOUT |
| `U5-N-ZERO-IDENTITY` | assignment_identity all-zero → LAYOUT |
| `U5-N-PROOF-ONLY-CHANGE` | same key+digest, proof bytes differ → CONFLICT（not duplicate） |
| `U5-N-PERMIT-NO-FENCE` | term mutation で旧 permit が consume 可能 → 不合格 |

### 13.3 Mutation budget

実装時: body の各 multi-byte field および reserved の **1-bit / 1-byte** 改変が reject または CONFLICT/DIGEST になること。silent accept 0。
ACK/REJECT の **body_length を ±1** する mutation は必ず reject。

## 14. Acceptance / evidence 境界

| Gate | 証明すること | 証明しないこと |
| --- | --- | --- |
| host pure vectors + mutation | wire/state/precedence/authority boundary | 実 USB |
| host full NCG1+NCL1 bridge | production codec 一致 | HIL |
| ESP-IDF compile/link | private sources が target で建つ | HIL / RF |
| Optional USB HIL | SET/ACK 往復 on real CDC | series complete |
| **Required for U5 complete 主張** | 上表 host gates green + §13 vectors + **`tools/u5_u6_docs_gate.py` check+self-test** | USB series complete; M4; FIELD production |

**compile ≠ HIL。** U5 complete は USB series complete を意味しない（U1/U2/U7 Required HIL は独立）。

## 15. Blockers（未解消なら当該 claim 実装不可）

| ID | 条件 | ブロックする claim |
| --- | --- | --- |
| **B-U5-AUTH-SUITE** | EXTERNAL_VERIFIED の suite/key/canonical signed bytes が Accepted 文書に無い | FIELD_PILOT/PRODUCTION での EXTERNAL 実装完了 / deployment-ready assignment |
| **B-U5-DEVICE-ID** | local `recipient_device_id` の provisioned 読み出し契約が port に無い | RECIPIENT 検査を含む U5 complete（LAB では test fixture ID で代替可と明記した host のみ進行可） |
| **B-U5-U4-SESSION** | U4 HELLO session engine 未実装 | 実 session 上の U5 integration（pure codec/state model は独立実装可） |
| **B-U5-ARW-FULL** | ARW を FULL `STORAGE_OK` で永続できない（ESP unproven 含む） | reconnect/reboot 耐性付き apply complete; FIELD apply |

Open/TBD/TODO は残さない。上記以外の実装判断は本章の default に従う。

## 16. Integration status（R2 Normative 正本 + 本 branch rebase 済み）

**成立済み:**
- `docs/24` + ADR-0004 は **現在の R2 Physical Compliance Permit Normative 正本**（main 統合済み）。
- 本 U5/U6 branch は origin/main へ **rebase 済み**。
- U5 の term/digest/`permit_bind_generation` fence と R2 bind 表は **本統合 diff で整合済み**（docs 契約の一致）。

| 文書 | 番号 | 状態 |
| --- | --- | --- |
| R2 | docs/24 + ADR-0004 | Normative docs freeze（**runtime implementation pending**） |
| U5 | docs/25 + ADR-0005 | Normative docs freeze; R2 bind/fence **整合済み** |
| U6 | docs/26 + ADR-0006 | Normative docs freeze |

**未完（誤主張禁止）:** R2 runtime body、U5/U6 runtime 実装、HIL、legal、RF、USB series complete、FIELD ready、production radio complete。
**GO 主張禁止:** 本章 docs freeze 単独では complete / ready を主張しない。**独立再レビュー合格まで GO 禁止**。

## 17. Acceptance checklist（本 docs freeze）

- [x] NCL1 envelope v1 維持; v1 catalog 非拡張; control protocol v2 exact
- [x] RuntimeRole / logical link role / CellOperatingAssignment 分離
- [x] exact catalog / layout / widths / endian / reserved（ACK **64** / REJECT **76** / SET 148+L; offset+end 一意）
- [x] identity/revision/epoch/controller term/cell/channel/role/capability/digest
- [x] LAB_ONLY と EXTERNAL_VERIFIED 境界; HELLO≠FIELD RF
- [x] volatile session-bound body; durable ARW floor; reconnect 後 lower 拒否; LKG body 非主張
- [x] stale/conflict/duplicate/higher-term precedence; ACK linearization + ARW FULL
- [x] copy-in/out; step sole drive; WOULD_BLOCK; pointer 借用禁止
- [x] vector set / host·ESP·HIL evidence 境界
- [x] blockers 明示; Open/TBD なし
- [x] permit bind = identity/revision/epoch/term/digest; mutation 時 outstanding permit atomic fence
- [x] selected_control_version **== 2** only; zero/nonzero closed; proof-only = CONFLICT
- [x] R2 docs/24 + ADR-0004 Normative 正本（main）へ rebase 済み; bind/fence 整合; runtime/HIL/legal/RF complete **非主張**; 独立再レビューまで GO 禁止
