# 24. R2 Physical Compliance Permit Authority

状態: **Normative freeze（docs only; R2 implementation pending; independent re-review GO 主張禁止）**<br>
対象: Physical Compliance Permit **authority object**（ADR-0003 **P1**）<br>
依存: [05](05-security-and-compliance.md)、[23](23-usb-radio-boundary.md)、[ADR-0003](adr/0003-radio-usb-dependency-direction.md)、[ADR-0004](adr/0004-r2-durable-permit-authority.md)、R1 `src/radio/radio_hal.h`、[platform.h](../include/ninlil/platform.h)、[version.h](../include/ninlil/version.h)、[20](20-m3-basic-esp-idf-platform-adapters.md)<br>
非対象: R3/R5/R4/R9/R6/R7/R10、Japan 数値、legal、public ABI、KGuard、M5 complete、HIL PASS、re-review PASS

## 0. 読み順

1. §1 非主張
2. [ADR-0004](adr/0004-r2-durable-permit-authority.md)
3. 本章 §3–§13（本文）と **§14**（vectors / semantic `pcp_r2_docs_gate` / GO 禁止）
4. R1 `radio_hal.h`（HAL status/watermark sealed ABI）

矛盾時: Accepted ADR > 本章 > docs/23 §9 > R1 header。

---

## 1. 位置付け・非主張

### 1.1 閉鎖一覧

| ID | 内容 |
| --- | --- |
| N1 | R1 watermark 非変更 + FIFO head-only consume |
| N2 | recover_clock exact |
| N3 | full live bind L in meta 200B |
| N4 | namespace-fixed authority_instance_id |
| N5 | storage op×status **唯一** mapping |
| N6 | recover I1–I14 provenance（outstanding==0 でも短絡しない） |
| N7 | private API exact（enum/struct/prototype self-contained） |
| N8 | clock sample: status 別 output 読取規則; TEMP の pre-init header は非 poison |
| N9 | CRC exact + golden |
| N10 | issue_generation == permit_sequence |
| N11 | Algorithm R / E / C / **A（advance expired head）** |
| N12 | physical transmitter ≠ Foundation bearer |
| N13 | validate 毎回 durable RO get 必須 |
| N14 | **expired head は H1 validate で止まる**ため owner 明示 `advance_expired_heads` で FIFO 前進 |
| N15 | CLOCK_FENCE 解除は **壊れた same-epoch を許可しない**; regression/perm/ill-formed/unknown は **fresh nonzero 128-bit epoch** 必須 |
| N16 | `bind_*` は **ops のみ**; `ops->user` が sole authority（別 user 引数禁止） |
| N17 | `publish_initial_meta` 全 field exact + **bind_live→publish** 唯一順 |
| N18 | `ram_validate` は seq+digest+epoch bind; matching consume のみ |
| N19 | terminal GC exact eligibility |
| N20 | **ceiling vs per-permit airtime** 分離（異 airtime outstanding≤8 可） |
| N21 | Algorithm R は **clock 非依存** |
| N22 | close/iter_close は void（failure mapping 無し） |

### 1.2 Forbidden claims

legal / Japan / R3–R10 complete / RF·HIL PASS / ledger complete / M5 / `compile==HIL` / logical TxPermit が physical 認可 / KGuard Core 必須 / **independent re-review GO**

### 1.3 用語

| 語 | 意味 |
| --- | --- |
| physical transmitter / radio path | R1 `transmitter_id`（16B） |
| Foundation bearer | `ninlil_bearer_ops_t`（physical RF 非認可） |
| head | `last_consumed_seq + 1` かつ state==ISSUED の seq（outstanding>0 のとき必ず存在） |
| terminal record | state ∈ {CONSUMED, REVOKED} |

---

## 2. 配置と TX / FIFO 順序

| ID | 役割 |
| --- | --- |
| P1-A | authority |
| P1-S | storage ops; namespace bytes `ninlil.pcp.v1` |
| P1-C | clock ops |
| P1-E | entropy ops（instance seed all-zero 時のみ） |
| H1 | R1 HAL |
| L1 | sole owner |

### 2.1 R1 call order（sealed; 変更しない）

```text
ninlil_radio_hal_transmit_with_permit:
  … → digest → validate → consume → edge×1
```

validate が `NINLIL_RADIO_HAL_EXPIRED` を返すと **consume は呼ばれない**（watermark 不変）。
よって **expired ISSUED head を consume 経路で REVOKED にする設計は H1 通常経路で到達不能**である。

### 2.2 Owner 決定的順序（MUST; N14）

sole owner は physical TX 試行ごとに次の **exact 順**のみ:

```text
S0  (optional) issue new permits only after head path is live or outstanding allows
S1  ninlil_pcp_advance_expired_heads(pcp, &out_error)
      → 0 個以上の expired head を durable REVOKED し last_consumed を前進
      → 返り値が PCP_OK かつ (outstanding==0 OR head is not expired under current clock)
S2  if need new plan: ninlil_pcp_issue(...)
S3  ninlil_radio_hal_transmit_with_permit(hal, snapshot, frame, …)
      // 内部: digest → validate → consume → edge
```

- S1 は **HAL を呼ばない**（non-destructive to RF; no edge）。
- S1 は clock sample + durable FULL のみ。
- S3 の validate が EXPIRED を返したら composition は **再 S1 してから再 S3**（同一 snapshot を consume させない）。
- Vectors: `A-ADV-1..4`。

---

## 3. Clock sample ABI（N8）

### 3.1 定数

| 名前 | 値 |
| --- | ---: |
| `NINLIL_ABI_VERSION` | `0x0001`（version.h） |
| `NINLIL_CLOCK_TRUSTED` | `1` |
| `NINLIL_CLOCK_UNCERTAIN` | `2` |
| `NINLIL_PORT_OK` | `0` |
| `NINLIL_PORT_TEMPORARY_FAILURE` | `1` |
| `NINLIL_PORT_PERMANENT_FAILURE` | `2` |

`ninlil_time_sample_t` は **platform.h が唯一の field 順正本**。offset は C compiler の `offsetof` / `_Static_assert` が検証する（Python ハードコード禁止）。

**ABI policy:** natural C11 alignment。`uint64_t` は align 8。したがって id128 終端 20 の後に pad 4 が入り、**POSIX LP64 と ESP32-S3 ILP32 の両方で**:

| field | type | offset | size |
| --- | --- | ---: | ---: |
| abi_version | u16 | 0 | 2 |
| struct_size | u16 | 2 | 2 |
| clock_epoch_id | u8[16] | 4 | 16 |
| *(pad)* | — | 20 | 4 |
| now_ms | u64 | **24** | 8 |
| trust | u32 | **32** | 4 |
| reserved_zero | u32 | **36** | 4 |
| sizeof | — | — | **40** |
| alignof | — | — | **≥8** |

| target | pointer | sizeof | now_ms | trust | evidence |
| --- | ---: | ---: | ---: | ---: | --- |
| POSIX host LP64 | 8 | 40 | 24 | 32 | `pcp_r2_time_sample_abi` CTest + `_Static_assert` |
| ESP32-S3 ILP32-class | 4 | 40 | 24 | 32 | `arm-none-eabi-gcc -c` static TU (`pcp_r2_time_sample_abi_ilp32`) および同一 `_Static_assert` |

数値が両 target で一致しても **「LP64 を全 target に流用した」とはみなさない**。各 target の compile evidence が必須。field 順入替は static_assert が落とす。

### 3.2 Call 前初期化（every `clock.now`）

```text
1. out_sample == NULL → 呼ばない
   - private API 文脈 → PCP_INVALID_ARGUMENT
   - validate/consume 文脈 → PERMIT_ERROR（R1）
2. memset(out_sample, 0, sizeof(*out_sample))
3. out_sample->abi_version = NINLIL_ABI_VERSION
4. out_sample->struct_size = sizeof(ninlil_time_sample_t)
5. clock.now(**ops->user**, out_sample) exactly once
```

ステップ 3–4 の **nonzero header は pre-init であり poison ではない**。
`ops->user` は bind された `ninlil_clock_ops_t.user` のみ（§11.5）。

### 3.3 Port status 別: output を読む / 無視する（唯一）

| `clock.now` status | sample フィールド読取 | 分類 | authority 動作 |
| --- | --- | --- | --- |
| `NINLIL_PORT_OK` (0) | **読む**（full validation §3.4） | OK-path | trust 分岐 |
| `NINLIL_PORT_TEMPORARY_FAILURE` (1) | **無視**（epoch/now/trust/reserved を compliance に使わない） | TEMP | CLOCK_UNCERTAIN map; **fence なし**; pre-init header 残存は **ill-formed としない** |
| `NINLIL_PORT_PERMANENT_FAILURE` (2) | **無視** | PERM | CLOCK_FAULT + CLOCK_FENCE |
| その他 / unknown | **無視** | CONTRACT | CLOCK_FAULT + CLOCK_FENCE |

**MUST NOT:** TEMP/PERM/unknown で `trust`/`epoch`/`now_ms` を読んで regression や valid_time を評価する。
**MUST NOT:** TEMP 後に「header nonzero ⇒ poison」と判定する。

### 3.4 OK のみ full validation（唯一）

`status == PORT_OK` のときだけ:

```text
V1. abi_version == NINLIL_ABI_VERSION
V2. struct_size >= sizeof(ninlil_time_sample_t) の platform 契約
    （短すぎる / 0 → ill-formed）
V3. reserved_zero == 0
V4. trust ∈ {TRUSTED=1, UNCERTAIN=2}
V5. clock_epoch_id 16B が all-zero でない
→ 全て成立: well-formed sample
→ 1 つでも不成立: ill-formed → CLOCK_FAULT + CLOCK_FENCE + fence_code=CLOCK_ILLFORMED（sample 不使用）
```

### 3.5 CLOCK_FENCE 設定原因コード（closed）

meta/`fence_code` および RAM に保持（解除判定に使用）:

| code | 値 | 設定契機 |
| --- | ---: | --- |
| `PCP_FC_NONE` | 0 | clear 後 |
| `PCP_FC_CLOCK_REGRESSION` | 1 | same-epoch `now < ram_trust_now` |
| `PCP_FC_CLOCK_PERM` | 2 | `PORT_PERMANENT_FAILURE` |
| `PCP_FC_CLOCK_ILLFORMED` | 3 | OK だが V1–V5 失敗 |
| `PCP_FC_CLOCK_UNKNOWN` | 4 | unknown port status |
| `PCP_FC_STORAGE` | 5 | STORAGE_FENCE 系（clock 解除対象外） |
| `PCP_FC_CORRUPT` | 6 | CORRUPT_FENCE 系 |

UNCERTAIN/TEMP は **CLOCK_FENCE を立てない**。

### 3.6 Half-open / RAM watermarks

```text
valid_time(S, permit) :=
  S well-formed AND S.trust==TRUSTED
  AND S.clock_epoch_id == permit.clock_epoch_id
  AND permit.not_before_ms <= S.now_ms
  AND S.now_ms < permit.expiry_ms

expired_time(S, permit) :=
  S well-formed AND S.trust==TRUSTED
  AND S.clock_epoch_id == permit.clock_epoch_id
  AND S.now_ms >= permit.expiry_ms
```

**ram_trust_***: issue/consume success FULL、advance_expired success、recover_clock OK、publish_initial_meta 成功時に TRUSTED sample で更新。

**ram_validate bind（N18）** — durable 0 の RAM のみ:

| field | 意味 |
| --- | --- |
| `ram_validate_valid` | 0/1 |
| `ram_validate_seq` | u64 permit_sequence |
| `ram_validate_digest[32]` | frame_digest |
| `ram_validate_epoch[16]` | clock_epoch_id of validate sample |
| `ram_validate_now_ms` | now_ms of validate sample |

**Set:** validate が R1 OK を返す直前に、durable get 済み ISSUED の `permit_sequence`/`frame_digest` と sample の epoch/now を書く。

**Clear（MUST; いずれかで valid=0）:**

| 契機 | clear |
| --- | --- |
| validate 失敗（any non-OK） | yes（set しない / 既存 clear） |
| 別 permit_sequence の validate OK | **overwrite**（旧 bind は消える） |
| matching consume 完了（OK または terminal FENCED/ERROR で put 試行後含む） | yes |
| matching consume で pre-put DENIED | **保持**（再試行用; seq+digest+epoch 一致時のみ rollback 判定に使用） |
| advance_expired / revoke_all / recover_* / shutdown / bind_live 成功 | yes force clear |
| issue 成功 | 不変（issue は validate bind を触らない） |

**consume での使用:**

```text
if ram_validate_valid
   AND permit.permit_sequence == ram_validate_seq
   AND permit.frame_digest exact== ram_validate_digest
   AND S.epoch == ram_validate_epoch
   AND S.now_ms < ram_validate_now_ms:
     → CLOCK_FAULT + F_c (validate→consume rollback)
else if ram_validate_valid but seq/digest/epoch mismatch:
     → rollback 判定に ram_validate を使わない（無視; clear はしない until success path）
```

same-epoch regression vs `ram_trust_*`: TRUSTED で `epoch==ram_trust_epoch && now < ram_trust_now` → F_c code=REGRESSION。

### 3.7 CLOCK_FENCE 解除（Algorithm C; N15 閉包）

**MUST NOT:** same-epoch の単調前進だけを、REGRESSION/PERM/ILLFORMED/UNKNOWN fence の解除根拠にする。

`fresh_epoch(S)` := well-formed TRUSTED
∧ epoch は **16-byte not-all-zero**（**各 byte nonzero は要求しない**; 1 byte でも non-zero なら可）
∧ `S.epoch != ram_trust_epoch` かつ `S.epoch != meta.last_trusted_epoch_id`
∧ もし outstanding ISSUED に `clock_epoch_id != S.epoch` があるなら **先に Algorithm R**（clock 不要）で outstanding=0、または FAIL `BUSY_OUTSTANDING`。

| fence_code 原因 | 解除に必要な sample | same-epoch 前進のみ |
| --- | --- | --- |
| REGRESSION (1) | **fresh_epoch(S)** + mono 規則（新 epoch の now は自由） | **禁止**（解除失敗） |
| PERM (2) | **fresh_epoch(S)** | 禁止 |
| ILLFORMED (3) | **fresh_epoch(S)** | 禁止 |
| UNKNOWN (4) | **fresh_epoch(S)** | 禁止 |
| 原因不明だが CLOCK bit のみ | **fresh_epoch(S)** として扱う | 禁止 |
| STORAGE/CORRUPT bits | recover_clock では **触らない** | n/a |

手順:

```text
C0 if CLOCK bit clear → NOOP OK
C1 sample S (§3)
C2 if not fresh_epoch(S) for codes 1–4 → FAIL; fence 維持
C3 if outstanding>0 and any ISSUED.epoch != S.epoch → FAIL BUSY_OUTSTANDING
   (caller が Algorithm R を先に実行; R は clock 不要)
C4 begin RW; meta.last_trusted_*=S; fence_bits&=~CLOCK; fence_code=0 if no other bits;
   put; commit FULL
C5 OK → ram_trust_*=S; clear RAM CLOCK; clear ram_validate
```

### 3.8 API 別 clock map

| 観測 | issue | validate | consume pre-put | advance_expired |
| --- | --- | --- | --- | --- |
| TEMP / OK+UNCERTAIN well-formed | PCP_CLOCK_UNCERTAIN | PERMIT_DENIED | CONSUME_DENIED | PCP_CLOCK_UNCERTAIN |
| PERM / ill-formed / unknown | PCP_CLOCK_FAULT+F_c | PERMIT_ERROR+F_c | CONSUME_FENCED+F_c | PCP_CLOCK_FAULT+F_c |
| regression | 同上 F_c code=1 | 同上 | 同上 | 同上 |
| TRUSTED + expired_time(head) | n/a | EXPIRED | bare: FENCED no put | **REVOKED advance** |
| TRUSTED + valid_time | issue 可 | OK 可 | consume 可 | no-op |

Issue 窓: `expiry > not_before`, `expiry > now`, TTL ≤ 600000。

---

## 4. FIFO・採番・invariants（N1,N6,N10）

### 4.1 規則

1. R1 watermark ABI 非変更。
2. consume OK / terminal burn 対象は **head のみ**（H1+R2 consume）。
3. non-head ISSUED → CONSUME_DENIED OUT_OF_ORDER。
4. 未発行 seq → CONSUME_FENCED FABRICATED。
5. `issue_generation := permit_sequence`（schema 1）。
6. caller issue request は **permit_sequence を持たない**。authority が `next_issue_seq` を採番。

### 4.2 Meta カウンタ意味

| field | 意味 |
| --- | --- |
| `next_issue_seq` | 次に発行する seq。初期 **1** |
| `last_consumed_seq` | terminal 化済み最大 seq。初期 **0**（まだ terminal なし） |
| `outstanding_count` | state==ISSUED の個数 |

### 4.3 Invariants I1–I14（**outstanding 値で短絡禁止**）

recover / 各 RW begin 後に **常に全条項を評価**する。`outstanding_count==0` でも I2/I5/I13/I14 を省略してはならない。

```text
I1  outstanding_count == |{iss records with state==ISSUED}|
I2  if outstanding_count > 0:
      let lo = last_consumed_seq + 1
      let hi = next_issue_seq - 1
      ISSUED set == {lo, lo+1, …, hi} exactly (continuous; no holes)
    if outstanding_count == 0:
      there MUST be zero ISSUED records
      (no "skip I2" — zero ISSUED is the only acceptable set)
I3  no record with state==ISSUED and permit_sequence <= last_consumed_seq
I4  for every iss record with state∈{CONSUMED,REVOKED}:
      permit_sequence <= last_consumed_seq
I5  next_issue_seq >= 1
    AND next_issue_seq != 0
    AND next_issue_seq < UINT64_MAX OR (next_issue_seq==UINT64_MAX ∧ no further issue)
    AND if any iss record exists:
          next_issue_seq == max(all permit_sequence among iss records) + 1
    AND if no iss records exist:
          next_issue_seq == last_consumed_seq + 1
          (history fully summarized by last_consumed; fresh: last=0,next=1)
I6  every iss key: len==20, "iss/"+16×[0-9a-f], key_seq==body.permit_sequence,
    body.authority_instance_id == meta.authority_instance_id
I7  key charset: only lowercase hex in seq part; uppercase/other → F_k
I8  all body.permit_sequence values distinct
I9  no body.permit_sequence ∈ {0, UINT64_MAX}
I10 meta key absent while any iss key present → F_k
    (meta absent && zero iss is handled only after successful open; see §6)
I11 every ISSUED: L_core exact-equal meta L_core
    AND body.max_airtime_us > 0
    AND body.max_airtime_us <= meta.bound_max_airtime_ceiling_us
    （max_airtime は per-permit; ceiling は meta。L_core 定義 §9）
I12 body.issue_generation == body.permit_sequence
I13 FIFO history (terminal side):
    for every integer s with 1 <= s <= last_consumed_seq:
      either (a) no iss key for s, OR (b) iss key exists with state∈{CONSUMED,REVOKED}
      MUST NOT exist ISSUED at s
I14 if outstanding_count == 0:
      EQUATION: next_issue_seq == last_consumed_seq + 1
```

**GC（N19; exact eligibility）:** §5.5。I1–I14 破れ → CORRUPT_FENCE。

### 4.4 Issue linearization

```text
1 sample clock (§3) TRUSTED path
2 structural request (§11): L_core exact==bound; 0 < max_airtime_us <= ceiling
3 begin RW
4 get meta; any fence → fail; check I1–I14
5 outstanding>=8 → PCP_CAPACITY
6 next_issue_seq >= UINT64_MAX → PCP_SEQ_EXHAUSTED
7 seq = next_issue_seq; build ISSUED (generation=seq; per-permit airtime)
8 put iss/seq; meta next+1, outstanding+1, last_trusted=S
   （meta ceiling は変更しない）
9 commit FULL → only OK returns snapshot with seq
```

### 4.5 Consume linearization（H1 経由; expired head 非担当）

```text
1 sample clock; validate→consume rollback check
2 structural snapshot (includes permit_sequence)
3 begin RW; meta; I1–I14
4 classify seq（get 結果込み; 唯一）:
   - seq <= last_consumed:
       get iss/seq
       - OK + state∈{CONSUMED,REVOKED} → CONSUME_FENCED ALREADY/REVOKED
       - NOT_FOUND → CONSUME_FENCED FABRICATED
       - other get status → §7.4 唯一 map
   - seq != last_consumed+1:
       get iss/seq
       - OK + ISSUED + seq in (last_consumed+1, next_issue-1] → CONSUME_DENIED OUT_OF_ORDER
       - NOT_FOUND or OK+non-ISSUED or seq>=next_issue → CONSUME_FENCED FABRICATED
   - seq == last_consumed+1 (head):
       continue step 5
5 get head（must succeed as ISSUED under I2; else F_k）; exact compare
6 time:
   - TEMP/UNCERTAIN/NOT_BEFORE → DENIED mutation 0
   - expired_time → CONSUME_FENCED EXPIRED mutation 0, head remains ISSUED
     （H1 通常不到達; bare consume でも advance はしない）
   - valid_time → put CONSUMED; outstanding-1; last_consumed=seq; last_trusted=S; commit OK
7 never DENIED after put
```

**唯一決定（N14）:** expired ISSUED の durable 前進は **§5 Algorithm A のみ**。consume は expired head を REVOKED にしない。

### 4.6 Validate（RO get 必須）

```text
1 sample clock
2 structural snapshot
3 begin RO
4 get meta (fence/I の RO 可能部分)
5 get iss/seq 必須; NOT_FOUND → PERMIT_DENIED FABRICATED
6 exact compare; state; time
7 rollback RO (fail → F_s; no ram_validate update)
8 all OK → set ram_validate bind（seq+digest+epoch+now）; return OK
```

---

## 5. Algorithm A / R / E / C / GC（N11,N14,N19,N21）

### 5.1 Algorithm A — `ninlil_pcp_advance_expired_heads`（progression exact）

```text
pre: storage+clock bound; not nested
A0 sample clock S once (§3) — loop 内で再 sample しない
A1 TEMP/UNCERTAIN → PCP_CLOCK_UNCERTAIN; durable 0; RAM trust 不変
A2 PERM/ill-formed/regression → F_c; PCP_CLOCK_FAULT; durable 0
A3 advanced_any = false
A4 loop:
   begin RW; verify I1–I14
   if outstanding_count == 0:
     rollback
     if advanced_any: SEMANTIC_SYNC_RAM_TRUST_FROM_META; clear ram_validate; return PCP_OK
     else: return PCP_OK  // no durable change; RAM trust 不変
   head = last_consumed_seq + 1
   get iss/head; state must ISSUED else F_k
   if not expired_time(S, head_record):
     rollback
     if advanced_any: SEMANTIC_SYNC_RAM_TRUST_FROM_META; clear ram_validate
     return PCP_OK   // head live/not-before; stop progression
   // expire head
   put REVOKED; outstanding_count -= 1; last_consumed_seq = head
   meta.last_trusted_epoch_id = S.epoch; meta.last_trusted_now_ms = S.now
   commit FULL
   A4-OK: advanced_any=true; PROGRESS_CONTINUE loop  // next head may be expired
   A4-COMMIT_UNKNOWN:
     F_s sticky; ram_trust_* を durable と推測同期しない
     ram_validate clear; return PCP_COMMIT_UNKNOWN
   A4-definite fail:
     staged 破棄; if advanced_any already committed prior iters:
       // prior FULL OK は線形化済み; RAM trust を **最後に成功した commit の S** へ
       SEMANTIC_SYNC_RAM_TRUST_TO_S; clear ram_validate
     return mapped fail
A5 (unreachable)
SEMANTIC_SYNC_RAM_TRUST_FROM_META := ram_trust_epoch/now ← meta.last_trusted_*
SEMANTIC_SYNC_RAM_TRUST_TO_S := ram_trust_epoch/now ← S
```

**Partial success:** 1 件以上 FULL OK 後に後続 fail/UNKNOWN でも、成功分の REVOKED/last_consumed は durable 正本。UNKNOWN 時は RAM trust を成功と断定しない（F_s）。definite fail 時は直前成功 commit の S へ RAM trust を合わせる（`SEMANTIC_SYNC_RAM_TRUST_*` 必須）。

### 5.2 Algorithm R — `revoke_all_outstanding`（**clock 非依存; N21**）

```text
pre: storage bound; clock MAY be unbound/faulted/FENCED
R0 MUST NOT call clock.now
R1 loop until outstanding==0:
   begin RW
   get meta; if outstanding==0: rollback; return PCP_OK
   head = last_consumed+1; get ISSUED (else F_k)
   put REVOKED; outstanding-1; last_consumed=head
   // last_trusted_* は変更しない（clock 非依存）
   clear ram_validate
   commit FULL
   COMMIT_UNKNOWN → F_s; return FAIL
   definite fail → mapped fail
R2 return PCP_OK
```

用途: profile bind 前、fresh epoch 前、clock 故障中の安全 drain。RF edge 0。

### 5.3 Algorithm E — issue 経路の new epoch 受入（唯一）

#### 5.3.1 Issue との txn / snapshot 線形化（E 入口）

```text
ISSUE-E entry (before any RW mutation for this issue call):
  I0  if in_api: return BUSY_REENTRY
  I1  sample clock → S  (exactly 1; §3). reuse 禁止の追加 sample なし
  I2  begin(READ_ONLY)   // snapshot txn T_ro; §13 shape
  I3  get meta → M_snap (must present; else INVALID_STATE / not published)
      read fields used by E:
        M_snap.last_trusted_epoch_id
        M_snap.last_trusted_now_ms
        M_snap.fence_bits (esp. CLOCK bit)
        M_snap.outstanding_count / next_issue_seq / last_consumed_seq
  I4  rollback T_ro  (MUST; fail → F_s; issue abort; no E)
      // after rollback, T_ro is dead; no reuse of T_ro handle
  I5  new_epoch := (S well-formed TRUSTED)
                 AND (S.epoch is 16B not-all-zero)
                 AND (S.epoch != M_snap.last_trusted_epoch_id)
                 // SEMANTIC: epoch_cmp_op is '!=' (not '==')
  I6  if (M_snap.fence_bits & CLOCK): return PCP_CLOCK_FAULT
      // E does not clear CLOCK_FENCE; recover_clock only
  I7  if not new_epoch: skip E entirely; proceed §4.4 structural with S
      (same S; no second clock sample)
  I8  else: run E-body below with inputs (S, M_snap); still no extra clock sample
```

**同時実行:** sole owner。recover/revoke/issue は in_api で直列。他 API が meta を変えた後の issue は I2–I4 の **新しい RO snapshot** を取る。

**§4.4 との関係:** E-body 成功後のみ §4.4 の structural + **新しい** begin(RW) で ISSUED put。E の RW txn と issue put の RW txn は **別 txn**（E commit 後に issue 用 begin）。

#### 5.3.2 E-body（single FULL atomic）

```text
E0  inputs: S (from I1), M_snap (from I3); new_epoch true
E1  begin(RW) → T_e   // independent of T_ro (already rolled back)
E2  get meta → M_live
    if M_live differs from M_snap on (last_trusted_epoch, outstanding,
       next_issue, last_consumed, fence_bits) beyond concurrent sole-owner
       impossibility: treat as CONTRACT F_k (should not happen under sole owner)
E3  E3_REVOKE_ALL_OUTSTANDING:
    while M_live.outstanding_count > 0:
      head = M_live.last_consumed_seq + 1
      get iss/head; must ISSUED else F_k
      put REVOKED; outstanding--; last_consumed=head
      // MUST revoke every outstanding; deleting this loop is Normative violation
E4  M_live.last_trusted_epoch_id = S.epoch
    M_live.last_trusted_now_ms = S.now
    // do NOT clear CLOCK fence bit here
E5  put meta M_live
E6  commit(FULL) T_e
E6-OK:
    ram_trust_* = S; clear ram_validate
    // T_e consumed; continue issue with same S at §4.4 step2+
E6-COMMIT_UNKNOWN:
    F_s set (STORAGE bit + fence_code=STORAGE); clear ram_validate
    // do NOT set ram_trust success
    return PCP_COMMIT_UNKNOWN  // issue aborts; see §5.3.3
E6-definite fail:
    non-commit; RAM trust unchanged; return mapped fail
```

**SEMANTIC: E3_REVOKE_ALL_OUTSTANDING while outstanding_count > 0 put REVOKED**

#### 5.3.3 E6 COMMIT_UNKNOWN / power-loss 収束（唯一; 揮発 S 非参照）

**原則:** restart / process death 後は issue の sample **S を参照してはならない**（揮発）。判定に使う epoch は **durable meta の `last_trusted_epoch_id` と ISSUED records の `clock_epoch_id` のみ**。

```text
U0  Immediate after E6 returns COMMIT_UNKNOWN (same process, before return to caller):
    U0a  T_e is consumed by commit() (platform: all statuses consume txn)
    U0b  RAM: fence_bits |= STORAGE; fence_code = PCP_FC_STORAGE; clear ram_validate
         // do NOT write ram_trust from S
    U0c  Best-effort durable fence sticky (optional attempt; must itself be closed):
         begin(RW) T_f
         get meta → M
         M.fence_bits |= STORAGE; M.fence_code = STORAGE (or keep stronger CORRUPT)
         put meta; commit FULL T_f
         if COMMIT_UNKNOWN again: retain RAM F_s only; do not loop forever (max 1 attempt)
         if definite fail: rollback if needed; retain RAM F_s
         if OK: durable+RAM F_s
         // cleanup: no live txn/iter after this step
    U0d  return PCP_COMMIT_UNKNOWN to caller (issue not successful)
    U0e  MUST NOT leave T_e/T_f live; MUST NOT issue OK

U1  Restart / later recovery entry (ninlil_pcp_recover or recover_storage):
    U1a  if storage_handle_live:
           // optional hygiene: close then reopen to drop ambiguous backend session
           close(handle); storage_handle_live=0   // close is void
    U1b  open(ns, schema=1) → handle; map §6.3
         if fail: return RECOVER_FAIL / UNSUPPORTED; issue not possible
    U1c  storage_handle_live=1

U2  Canonical EMPTY/full scan (§12 CANONICAL_SCAN_MODE_A empty-prefix full namespace):
    begin RO; iter_open(empty prefix); classify ALL keys; iter_close; rollback RO
    foreign → F_k; CRC fail → F_k; I1–I14 fail → F_k
    // durable_epoch := meta.last_trusted_epoch_id from scan (if meta present)
    // NEVER consult process-local S from the failed issue

U3  Dual-truth convergence (observe-only; no speculation):
    After scan, exactly one of:
      C_COMMITTED: meta present AND outstanding_count==0
                   AND every iss key is terminal or absent for 1..last_consumed
                   AND I1–I14 hold
                   → E's revoke+baseline may have committed; durable_epoch is new baseline
      C_PRE_E:     meta present AND I1–I14 hold AND
                   (outstanding_count>0 OR iss ISSUED remain)
                   → E did not commit; durable_epoch is pre-E baseline
      C_EMPTY:     meta absent AND zero keys → EMPTY_OK path (unrelated to E)
      C_CORRUPT:   otherwise → F_k; RECOVER_FAIL

U4  STORAGE fence clear (only C_COMMITTED or C_PRE_E with clean I*):
    begin RW; get meta; fence_bits &= ~STORAGE if no CORRUPT;
    put meta; commit FULL
    if COMMIT_UNKNOWN: retain F_s; close handle; return RECOVER_FAIL
       // next recover must U1 reopen + U2 rescan (loop bound: caller retries; no auto infinite)
    if definite fail: rollback; retain F_s; return mapped fail
    if OK: clear RAM STORAGE bit; fence_code clear if no other bits
    // always: no live txn after

U5  Post-recover RAM rebuild (no volatile S):
    ram_trust_epoch := meta.last_trusted_epoch_id
    ram_trust_now   := meta.last_trusted_now_ms
    ram_trust.valid := 1 if meta present else 0
    clear ram_validate
    published := 1 if meta present else 0

U6  Issue-possible unique condition (all required):
    published==1
    AND storage_handle_live==1
    AND (fence_bits & (STORAGE|CLOCK|CORRUPT)) == 0
    AND I1–I14 hold on last successful scan
    AND clock_bound && live_bound
    → issue may start (new sample S'; may re-enter E if S.epoch != meta.last_trusted)
```

**MUST NOT:** STORAGE bit だけ clear して scan/I* を省略。
**MUST NOT:** UNKNOWN 後に issue OK。
**MUST NOT:** recovery で failed issue の S.epoch を参照。
### 5.4 Algorithm C — `recover_clock`

§3.7 に同一（codes 1–4 は fresh_epoch 必須; **not-all-zero 16B**）。
### 5.5 Terminal GC — `ninlil_pcp_gc_terminal_records`（optional API; exact）

**Eligibility（全て必須）:**

```text
G1 state ∈ {CONSUMED, REVOKED}
G2 permit_sequence <= last_consumed_seq
G3 state != ISSUED（自明）
G4 erase 後も I1–I14 が成立すること（特に I5/I13/I14）
G5 単一 FULL txn 内で erase する key 集合は事前に RO で列挙し、
   max erase count ≤ PCP_MAX_OUTSTANDING (8) per call
```

```text
begin RW
get meta; verify I*
for each eligible key in caller set or scan:
  erase key
put meta unchanged counters (last_consumed/next/outstanding MUST NOT change)
commit FULL
COMMIT_UNKNOWN → F_s
```

**MUST NOT:** decrease last_consumed/next; erase ISSUED; erase seq > last_consumed。

---

## 6. Storage namespace 契約（N; open NOT_FOUND）

### 6.1 platform.h API（唯一）

```text
open(user, storage_namespace, expected_schema, out_handle) → ninlil_storage_status_t
close(user, handle) → void
// create-namespace 専用 public API は存在しない
```

### 6.2 R2 が要求する port 契約（P1-S）

R2 に bind してよい storage 実装は次を **全て**満たす:

| 規則 | 内容 |
| --- | --- |
| P-OPEN-1 | `open(ns=ninlil.pcp.v1, expected_schema=1)` が成功するとき **必ず** valid handle を返す |
| P-OPEN-2 | namespace が未存在のとき: **empty namespace を作成して OK** する（create-on-open）。**NOT_FOUND を返してはならない** |
| P-OPEN-3 | 既存 namespaceで schema≠1: `UNSUPPORTED_SCHEMA` |
| P-OPEN-4 | create 不能な media: R2 **unsupported**; composition は bind しない |

### 6.3 Authority 側 open 結果（唯一 mapping）

| open status | fence | authority | EMPTY? |
| --- | --- | --- | --- |
| OK | — | handle 所有; recover へ | 後段 get meta で判定 |
| NOT_FOUND | — | **PCP_STORAGE_UNSUPPORTED** fail-closed; handle なし | **EMPTY としない** |
| BUFFER_TOO_SMALL | F_k | PCP_CORRUPT_FENCE | no |
| NO_SPACE | — | PCP_STORAGE_IO / CAPACITY fail Z | no |
| IO_ERROR | F_s | PCP_STORAGE_IO | no |
| CORRUPT | F_k | PCP_CORRUPT_FENCE | no |
| COMMIT_UNKNOWN | F_s | PCP_COMMIT_UNKNOWN | no |
| BUSY | — | PCP_BUSY retryable Z | no |
| UNSUPPORTED_SCHEMA | — | PCP_STORAGE_UNSUPPORTED | no |
| unknown | F_k | PCP_CORRUPT_FENCE | no |

### 6.4 EMPTY の唯一定義

```text
open == OK
AND recover_storage RO scan:
  meta key absent
  AND zero iss keys
→ EMPTY_OK → caller は ninlil_pcp_publish_initial_meta
```

meta absent + iss>0 → F_k（I10）。

### 6.5 Ownership

```text
bind_storage: store ops pointer only
first recover or publish path: open once; authority owns handle
shutdown/unbind: no live txn/iter; close; handle=NULL
```

---

## 7. Storage op × status 唯一 mapping（N5）

凡例: **Z**=成功なし・公開 mutation なし。**F_s/F_c/F_k**=sticky fence。
R1 列は validate/consume 文脈。issue/advance は §12 private status。

### 7.1 open

| status | mut | fence | result |
| ---: | --- | --- | --- |
| 0 OK | 0 | — | handle live |
| 1 NOT_FOUND | 0 | — | PCP_STORAGE_UNSUPPORTED |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | — | PCP_STORAGE_IO |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | — | PCP_STORAGE_UNSUPPORTED |
| other | 0 | F_k | PCP_CORRUPT_FENCE |

### 7.2 close（platform: **void**; N22）

```text
close(user, handle) → void   // platform.h; status を返さない
```

Authority 契約:

- call 前: live txn=0 かつ live iter=0（違反は call しない; 検出したら F_k で shutdown 失敗扱いは **close を呼ぶ前**）
- call 後: handle を NULL 化; **close の failure mapping は存在しない**（void）
- **MUST NOT** close に status 表や IO/CORRUPT マップを定義する
### 7.3 begin

| status | mut | fence | validate | consume pre-put | issue/advance |
| ---: | --- | --- | --- | --- | --- |
| 0 OK | 0 | — | cont | cont | cont |
| 1 NOT_FOUND | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | — | PERMIT_ERROR | CONSUME_ERROR | PCP_STORAGE_IO |
| 4 IO_ERROR | 0 | F_s | PERMIT_ERROR | CONSUME_ERROR | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PERMIT_ERROR | CONSUME_ERROR | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PERMIT_ERROR | CONSUME_DENIED | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |

### 7.4 get

| status | mut | fence | validate | consume pre-put | issue/advance/recover |
| ---: | --- | --- | --- | --- | --- |
| 0 OK | 0 | — | cont if len exact | cont if len exact | cont if len exact |
| 0 OK len≠200/232 | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 1 NOT_FOUND | 0 | — | key absent（R1/private へは §4 分類が唯一マップ: validate iss miss→PERMIT_DENIED; consume §4.5 分類; recover meta miss→§6.4） | same | same |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 4 IO_ERROR | 0 | F_s | PERMIT_ERROR | CONSUME_ERROR | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PERMIT_ERROR | CONSUME_ERROR | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PERMIT_ERROR | CONSUME_DENIED | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PERMIT_ERROR | CONSUME_ERROR | PCP_CORRUPT_FENCE |

### 7.5 put

| status | mut | fence | issue | consume after put intent | advance |
| ---: | --- | --- | --- | --- | --- |
| 0 OK | staged | — | cont | cont | cont |
| 1 NOT_FOUND | 0 | F_k | PCP_CORRUPT_FENCE | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | — | PCP_CAPACITY | CONSUME_ERROR | PCP_STORAGE_IO |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO | CONSUME_ERROR | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN | CONSUME_FENCED | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY | CONSUME_DENIED | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PCP_CORRUPT_FENCE | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PCP_CORRUPT_FENCE | CONSUME_ERROR | PCP_CORRUPT_FENCE |

### 7.6 erase

| status | mut | fence | result |
| ---: | --- | --- | --- |
| 0 OK | staged | — | cont |
| 1 NOT_FOUND | 0 | — | cont（idempotent GC） |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | — | PCP_STORAGE_IO |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PCP_CORRUPT_FENCE |

### 7.7 iter_open

| status | mut | fence | result |
| ---: | --- | --- | --- |
| 0 OK | 0 | — | cont |
| 1 NOT_FOUND | 0 | F_k | PCP_CORRUPT_FENCE |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | — | PCP_STORAGE_IO |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PCP_CORRUPT_FENCE |

### 7.8 iter_next

| status | mut | fence | result |
| ---: | --- | --- | --- |
| 0 OK | 0 | — | classify key; I6–I12 |
| 1 NOT_FOUND | 0 | — | end of iteration |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | F_k | PCP_CORRUPT_FENCE |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PCP_CORRUPT_FENCE |

### 7.9 iter_close（platform: **void**; N22）

```text
iter_close(user, iter) → void
```

- open 成功した iter に対し exactly once
- invalid iter を渡さない（precondition; 検知は call 前 F_k）
- **failure status mapping なし**

### 7.10 capacity

| status | mut | fence | result |
| ---: | --- | --- | --- |
| 0 OK | 0 | — | ignore for admit（observability only） |
| 1 NOT_FOUND | 0 | F_k | PCP_CORRUPT_FENCE |
| 2 BUFFER_TOO_SMALL | 0 | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | 0 | F_k | PCP_CORRUPT_FENCE |
| 4 IO_ERROR | 0 | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | 0 | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | 0 | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | 0 | — | PCP_BUSY |
| 8 UNSUPPORTED_SCHEMA | 0 | F_k | PCP_CORRUPT_FENCE |
| other | 0 | F_k | PCP_CORRUPT_FENCE |

### 7.11 commit(FULL)

| status | public mut | fence | consume | issue/advance |
| ---: | --- | --- | --- | --- |
| 0 OK | yes | — | OK path | OK path |
| 1 NOT_FOUND | no | F_k | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 2 BUFFER_TOO_SMALL | no | F_k | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | no | — | CONSUME_ERROR | PCP_STORAGE_IO |
| 4 IO_ERROR | no | F_s | CONSUME_ERROR | PCP_STORAGE_IO |
| 5 CORRUPT | no | F_k | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | unknown | F_s | CONSUME_FENCED | PCP_COMMIT_UNKNOWN |
| 7 BUSY | no | F_s | CONSUME_ERROR | PCP_COMMIT_UNKNOWN |
| 8 UNSUPPORTED_SCHEMA | no | F_k | CONSUME_ERROR | PCP_CORRUPT_FENCE |
| other | no | F_k | CONSUME_ERROR | PCP_CORRUPT_FENCE |

txn handle は全 status で consume 済み。BUSY on commit → F_s（ambiguous）。

**SEMANTIC: commit status=6 → fence=F_s; consume=CONSUME_FENCED; never CONSUME_DENIED; never OK**

### 7.12 rollback

| status | fence | result |
| ---: | --- | --- |
| 0 OK | — | staged discarded |
| 1 NOT_FOUND | F_s | PCP_STORAGE_IO; handle dead |
| 2 BUFFER_TOO_SMALL | F_k | PCP_CORRUPT_FENCE |
| 3 NO_SPACE | F_s | PCP_STORAGE_IO |
| 4 IO_ERROR | F_s | PCP_STORAGE_IO |
| 5 CORRUPT | F_k | PCP_CORRUPT_FENCE |
| 6 COMMIT_UNKNOWN | F_s | PCP_COMMIT_UNKNOWN |
| 7 BUSY | F_s | PCP_STORAGE_IO |
| 8 UNSUPPORTED_SCHEMA | F_k | PCP_CORRUPT_FENCE |
| other | F_k | PCP_CORRUPT_FENCE |

Durability: authority mutation は **FULL=3 only**。

---

## 8. Record layout / CRC

### 8.1 定数

| 名前 | 値 |
| --- | ---: |
| PCP_SCHEMA_VERSION | 1 |
| PCP_MAGIC | 0x31504350 |
| PCP_NAMESPACE | `ninlil.pcp.v1` (12) |
| PCP_META_KEY | `meta` (4) |
| PCP_ISS_KEY_BYTES | 20 |
| PCP_META_VALUE_BYTES | 200 |
| PCP_ISSUED_VALUE_BYTES | 232 |
| PCP_MAX_OUTSTANDING | 8 |
| PCP_MAX_PERMIT_TTL_MS | 600000 |
| PCP_OBJECT_BYTES | 4096 |
| PCP_OBJECT_ALIGN | 8 |
| PCP_HINT_BYTES | 160 |

### 8.2 Meta 200B LE（exact offsets）

| off | sz | field |
| ---: | ---: | --- |
| 0 | 4 | magic |
| 4 | 2 | schema |
| 6 | 1 | meta_state 1=ACTIVE 2=FENCED |
| 7 | 1 | fence_bits b0=STORAGE b1=CLOCK b2=CORRUPT |
| 8 | 16 | authority_instance_id |
| 24 | 8 | next_issue_seq |
| 32 | 8 | last_consumed_seq |
| 40 | 4 | outstanding_count |
| 44 | 4 | fence_code |
| 48 | 16 | bound_hardware_profile_id |
| 64 | 4 | bound_hardware_profile_rev |
| 68 | 16 | bound_regulatory_profile_id |
| 84 | 4 | bound_regulatory_profile_rev |
| 88 | 16 | bound_site_assignment_id |
| 104 | 4 | bound_site_assignment_rev |
| 108 | 8 | bound_site_assignment_epoch |
| 116 | 16 | bound_transmitter_id |
| 132 | 4 | bound_channel_id |
| 136 | 4 | bound_phy.bandwidth_hz |
| 140 | 1 | bound_phy.spreading_factor |
| 141 | 1 | bound_phy.coding_rate_denom |
| 142 | 2 | bound_phy.preamble_symbols |
| 144 | 4 | bound_phy.tx_power_mdb |
| 148 | 4 | bound_phy.phy_flags |
| 152 | 4 | **bound_max_airtime_ceiling_us**（L ceiling; 全 permit の上限） |
| 156 | 8 | assignment_generation |
| 164 | 16 | last_trusted_epoch_id |
| 180 | 8 | last_trusted_now_ms |
| 188 | 8 | reserved_zero |
| 196 | 4 | crc32 of `[0..196)` |

### 8.3 Issued 232B LE（exact offsets）

| off | sz | field |
| ---: | ---: | --- |
| 0 | 4 | magic |
| 4 | 2 | schema |
| 6 | 1 | state 1=ISSUED 2=CONSUMED 3=REVOKED |
| 7 | 1 | flags 0 |
| 8 | 8 | permit_sequence |
| 16 | 16 | clock_epoch_id |
| 32 | 8 | not_before_ms |
| 40 | 8 | expiry_ms |
| 48 | 16 | hardware_profile_id |
| 64 | 4 | hardware_profile_rev |
| 68 | 16 | regulatory_profile_id |
| 84 | 4 | regulatory_profile_rev |
| 88 | 16 | site_assignment_id |
| 104 | 4 | site_assignment_rev |
| 108 | 8 | site_assignment_epoch |
| 116 | 16 | transmitter_id |
| 132 | 4 | channel_id |
| 136 | 4 | phy.bandwidth_hz |
| 140 | 1 | phy.spreading_factor |
| 141 | 1 | phy.coding_rate_denom |
| 142 | 2 | phy.preamble_symbols |
| 144 | 4 | phy.tx_power_mdb |
| 148 | 4 | phy.phy_flags |
| 152 | 32 | frame_digest |
| 184 | 4 | frame_digest_algorithm |
| 188 | 4 | frame_byte_length |
| 192 | 4 | **max_airtime_us**（per-permit expected/conservative; ≤ meta ceiling） |
| 196 | 16 | authority_instance_id |
| 212 | 8 | issue_generation（== permit_sequence） |
| 220 | 8 | reserved_zero |
| 228 | 4 | crc32 of `[0..228)` |

### 8.4 CRC

| item | value |
| --- | --- |
| poly | 0xEDB88320 |
| init | 0xFFFFFFFF |
| xorout | 0xFFFFFFFF |
| refin | true |
| refout | true |

Golden: G0 empty→`00000000`; G1 `123456789`→`cbf43926`; G2 `abc`→`352441c2`; G3 196 zero→`ea76f752`; G4 228 zero→`bcc91f52`; G5 magic+192 zero→`b79c907c`; G6 `iss/0000000000000001`→`f186f959`。

---

## 9. Live bind / airtime 分離（N3,N12,N20）

### 9.1 L_core vs airtime

| 集合 | fields | meta | ISSUED | issue 検査 |
| --- | --- | --- | --- | --- |
| **L_core** | hw id/rev, reg id/rev, site id/rev/epoch, transmitter_id, channel_id, phy.* | bound_* | same | plan **exact == bound** |
| **ceiling** | max airtime upper bound | `bound_max_airtime_ceiling_us` | — | — |
| **per-permit airtime** | expected/conservative ToA for this frame | — | `max_airtime_us` | `0 < plan ≤ ceiling` |

**MUST:** outstanding ≤8 の各 ISSUED が **異なる** `max_airtime_us` を持てる（いずれも ≤ ceiling）。
**MUST NOT:** 全 outstanding に同一 airtime を強制する cohort 制約を導入する。

**H1 整合:** R1 は live.max_airtime と permit の **exact** 比較。owner は各 TX 直前に `set_live_binding` で **当該 permit の max_airtime_us**（および L_core）を載せる。ceiling は R2 issue 専用; H1 live に ceiling を載せたまま異 airtime permit を流すと LIVE_MISMATCH。

`bind_live_profile` 入力: R1 `live_binding` と同 layout。**`live.max_airtime_us` は ceiling として meta に格納**（field 名は wire 上 ceiling）。zero ceiling 禁止。

outstanding==0 のみ bind 可。choreography: R or drain → bind_live → HAL set_live（TX 時は per-permit airtime で更新可）。

### 9.2 `publish_initial_meta` exact（N17）

**唯一順序:**

```text
1 init_object
2 bind_storage(ops)     // ops->user sole
3 bind_clock(ops)
4 bind_entropy(ops) if seed all-zero path
5 bind_live_profile(live)  // L_core nonzero + ceiling>0; RAM only until publish
6 publish_initial_meta(seed)
```

**禁止:** publish 前に live 未 bind; zero-L; meta 既存での publish; issue 前の publish スキップ。

**publish 手順（EMPTY 定義は §6.4 / §12 と同一; full-namespace scan 必須）:**

```text
P0 open namespace (create-on-open); fail → map §6.3
P1 begin RO
P1-SCAN  PUBLISH_FULL_NAMESPACE_SCAN (same grammar as §12 recover):
         iter_open(prefix = empty bytes_view length 0)
         // REQUIRED empty-prefix; FORBIDDEN sole iss/ scan
         meta_count=0; iss_count=0; foreign=0
         loop iter_next:
           OK:
             KEY_META → meta_count++; value validate CRC (if present → not empty)
             KEY_ISS  → iss_count++
             KEY_FOREIGN → foreign=1; reason=FOREIGN_KEY
           NOT_FOUND → end
           other → map §7.8; CLEANUP_FAIL
         iter_close
         if foreign: rollback; F_k; return RECOVER_FAIL/CORRUPT
         if meta_count>0: rollback; PCP_INVALID_STATE  // already published
         if iss_count>0: rollback; F_k  // meta absent + iss = not EMPTY (same as §12 R-S5)
         // EMPTY iff meta_count==0 AND iss_count==0 AND foreign==0
P2 rollback RO
P3 sample clock S; require TRUSTED well-formed (TEMP→UNCERTAIN fail; no fence unless PERM)
P4 instance_id = seed nonzero ? seed : entropy.fill(16); all-zero fail
P5 build meta value exact:
   magic, schema=1
   meta_state=ACTIVE(1)
   fence_bits=0
   fence_code=0
   authority_instance_id = instance_id
   next_issue_seq=1
   last_consumed_seq=0
   outstanding_count=0
   bound L_core + bound_max_airtime_ceiling_us from RAM live
   assignment_generation=1
   last_trusted_epoch_id = S.epoch
   last_trusted_now_ms = S.now
   reserved_zero=0
   body_crc32
P6 begin RW; put meta; commit FULL
   COMMIT_UNKNOWN → F_s; MUST NOT return OK; recover_storage 後も meta 曖昧なら F_s
   fail → no OK
P7 OK → ram_trust_*=S; clear ram_validate; return PCP_OK
```

**SEMANTIC: PUBLISH_FULL_NAMESPACE_SCAN uses iter_open empty prefix and classifies KEY_FOREIGN**
Crash: P5 前 durable 0; P6 UNKNOWN → F_s。
### 9.3 Identity

instance_id: publish のみ mint; re-init は meta から採用。recover 詳細は §12。

---

## 10. Private API exact（N7）

**Compile 正本:** `src/radio/pcp_authority.h`（C11 complete type; production-private）。
本章の数値・ownership は header と **一致必須**。省略 `{…}` 記法は規範に使わない。header が欠ける / 非 complete なら docs freeze 不成立。

### 10.1 Status enum（numeric; header `NINLIL_PCP_*`）

| name | value |
| --- | ---: |
| NINLIL_PCP_OK | 0 |
| NINLIL_PCP_INVALID_ARGUMENT | 1 |
| NINLIL_PCP_INVALID_STATE | 2 |
| NINLIL_PCP_STRUCT | 3 |
| NINLIL_PCP_CLOCK_UNCERTAIN | 4 |
| NINLIL_PCP_CLOCK_FAULT | 5 |
| NINLIL_PCP_PROFILE_MISMATCH | 6 |
| NINLIL_PCP_CAPACITY | 7 |
| NINLIL_PCP_SEQ_EXHAUSTED | 8 |
| NINLIL_PCP_STORAGE_FENCE | 9 |
| NINLIL_PCP_CORRUPT_FENCE | 10 |
| NINLIL_PCP_COMMIT_UNKNOWN | 11 |
| NINLIL_PCP_STORAGE_IO | 12 |
| NINLIL_PCP_BUSY | 13 |
| NINLIL_PCP_BUSY_OUTSTANDING | 14 |
| NINLIL_PCP_BUSY_REENTRY | 15 |
| NINLIL_PCP_ALIAS | 16 |
| NINLIL_PCP_UNBOUND_STORAGE | 17 |
| NINLIL_PCP_UNBOUND_CLOCK | 18 |
| NINLIL_PCP_UNBOUND_ASSIGNMENT | 19 |
| NINLIL_PCP_RECOVER_FAIL | 20 |
| NINLIL_PCP_STORAGE_UNSUPPORTED | 21 |
| NINLIL_PCP_SHUTDOWN | 22 |
| NINLIL_PCP_EMPTY_OK | 23 |

underlying type: `uint32_t`。

### 10.2 Reason enum（numeric）

```text
PCP_REASON_NONE                 0
PCP_REASON_NULL_ARG             1
PCP_REASON_STRUCT_INVALID       2
PCP_REASON_UNBOUND_STORAGE      3
PCP_REASON_UNBOUND_CLOCK        4
PCP_REASON_UNBOUND_ASSIGNMENT   5
PCP_REASON_CLOCK_UNCERTAIN      6
PCP_REASON_CLOCK_FAULT          7
PCP_REASON_EPOCH_MISMATCH       8
PCP_REASON_NOT_BEFORE           9
PCP_REASON_EXPIRED             10
PCP_REASON_PROFILE_MISMATCH    11
PCP_REASON_FABRICATED          12
PCP_REASON_ALREADY_CONSUMED    13
PCP_REASON_REVOKED             14
PCP_REASON_CAPACITY            15
PCP_REASON_SEQ_EXHAUSTED       16
PCP_REASON_STORAGE_FENCE       17
PCP_REASON_CORRUPT_FENCE       18
PCP_REASON_COMMIT_UNKNOWN      19
PCP_REASON_STORAGE_IO          20
PCP_REASON_STORAGE_CORRUPT     21
PCP_REASON_BUSY_REENTRY        22
PCP_REASON_BUSY_OUTSTANDING    23
PCP_REASON_ALIAS               24
PCP_REASON_COUNTER_SAT         25
PCP_REASON_SHUTDOWN            26
PCP_REASON_INVALID_STATE       27
PCP_REASON_CONTRACT            28
PCP_REASON_OUT_OF_ORDER        29
PCP_REASON_INSTANCE_MISMATCH   30
PCP_REASON_RECOVER_FAIL        31
PCP_REASON_FOREIGN_KEY         32
PCP_REASON_STORAGE_UNSUPPORTED 33
PCP_REASON_HEAD_ADVANCED       34
```

### 10.3 Stage enum（header と完全一致; underlying uint32_t）

| name | value |
| --- | ---: |
| NINLIL_PCP_STAGE_NONE | 0 |
| NINLIL_PCP_STAGE_INIT | 1 |
| NINLIL_PCP_STAGE_BIND | 2 |
| NINLIL_PCP_STAGE_RECOVER | 3 |
| NINLIL_PCP_STAGE_PUBLISH | 4 |
| NINLIL_PCP_STAGE_ISSUE | 5 |
| NINLIL_PCP_STAGE_VALIDATE | 6 |
| NINLIL_PCP_STAGE_CONSUME | 7 |
| NINLIL_PCP_STAGE_ADVANCE | 8 |
| NINLIL_PCP_STAGE_REVOKE | 9 |
| NINLIL_PCP_STAGE_SHUTDOWN | 10 |
| NINLIL_PCP_STAGE_GC | 11 |

**SEMANTIC: STAGE_TABLE_COMPLETE 0..11 includes GC=11**
### 10.4–10.6 Types / object / prototypes

**唯一の C 正本:** [`src/radio/pcp_authority.h`](../src/radio/pcp_authority.h)

含むもの（省略禁止）:

- 全 `NINLIL_PCP_*` status/reason/stage/fence/lifecycle `#define`（underlying `uint32_t`）
- `ninlil_pcp_error_t` 全 field type/order（status, stage, reason, reserved_zero, hint[160]）
- `ninlil_pcp_issue_request_t` 全 field（**permit_sequence 無し**）
- `ninlil_pcp_r2_stats_t` 全 24×u64 field（void* 禁止; 下表が field 集合/順序/offset 正本）
- complete `struct ninlil_pcp` / `ninlil_pcp_object_t` / `NINLIL_PCP_OBJECT_INIT`
- `ninlil_pcp_object_size` / `object_align`（inline sizeof/_Alignof）
- `_Static_assert` ceiling/align/stats **全 field** offsetof + `sizeof(((T*)0)->field)==sizeof(uint64_t)`
- bind_* without user; ops→user sole
- 全 function prototypes（init/shutdown/bind/publish/recover/issue/advance/revoke/gc/validate/consume/permit_ops/stats/last_error）
- ownership/lifetime comment block

**SEMANTIC: STATS_FIELDS_24_U64** — exact order / offset / type（padding hole 禁止; 任意 field を `uint8_t` 等へ narrowing しても `sizeof(stats)==192` の padding で greening 不可）:

| i | off | field | type |
| ---: | ---: | --- | --- |
| 0 | 0 | issue_ok | uint64_t |
| 1 | 8 | issue_deny | uint64_t |
| 2 | 16 | validate_ok | uint64_t |
| 3 | 24 | validate_deny | uint64_t |
| 4 | 32 | validate_error | uint64_t |
| 5 | 40 | consume_ok | uint64_t |
| 6 | 48 | consume_denied | uint64_t |
| 7 | 56 | consume_fenced | uint64_t |
| 8 | 64 | consume_error | uint64_t |
| 9 | 72 | advance_ok | uint64_t |
| 10 | 80 | advance_nop | uint64_t |
| 11 | 88 | revoke_ok | uint64_t |
| 12 | 96 | recover_ok | uint64_t |
| 13 | 104 | recover_fail | uint64_t |
| 14 | 112 | fence_set | uint64_t |
| 15 | 120 | storage_commit_unknown | uint64_t |
| 16 | 128 | fifo_out_of_order | uint64_t |
| 17 | 136 | reentry_reject | uint64_t |
| 18 | 144 | alias_reject | uint64_t |
| 19 | 152 | gc_erased | uint64_t |
| 20 | 160 | reserved_zero_0 | uint64_t |
| 21 | 168 | reserved_zero_1 | uint64_t |
| 22 | 176 | reserved_zero_2 | uint64_t |
| 23 | 184 | reserved_zero_3 | uint64_t |

`sizeof(ninlil_pcp_r2_stats_t) == 192`; `_Alignof == 8`. header + consumer compile + static TU が全 field に width assert を持つ。

**Evidence:** CTest `pcp_r2_consumer_compile` が private header を include して native C11 strict compile/link（型・sizeof のみ; authority body 未実装でも header contract は成立）。
### 10.7 Issue expiry 違反 → private status/reason（唯一）

| 条件 | reason | status | durable |
| --- | ---: | ---: | --- |
| `expiry_ms <= not_before_ms` | 2 STRUCT_INVALID | 3 PCP_STRUCT | 0 |
| `expiry_ms <= sample.now_ms`（既閉窓） | **10 EXPIRED** | **1 PCP_INVALID_ARGUMENT** | 0 |
| `expiry_ms - not_before_ms > 600000` | 2 STRUCT_INVALID | 3 PCP_STRUCT | 0 |
| sample TEMP/UNCERTAIN | 6 CLOCK_UNCERTAIN | 4 PCP_CLOCK_UNCERTAIN | 0 |
| sample PERM/ill-formed/regression | 7 CLOCK_FAULT | 5 PCP_CLOCK_FAULT | 0 |

out_snapshot: 失敗時 **zero**（partial fill 禁止）。

### 10.8 reason → private status（issue/advance/recover）

| reason | status |
| ---: | ---: |
| 0 NONE | 0 OK |
| 1 NULL_ARG | 1 INVALID_ARGUMENT |
| 2 STRUCT_INVALID | 3 STRUCT |
| 3 UNBOUND_STORAGE | 17 UNBOUND_STORAGE |
| 4 UNBOUND_CLOCK | 18 UNBOUND_CLOCK |
| 5 UNBOUND_ASSIGNMENT | 19 UNBOUND_ASSIGNMENT |
| 6 CLOCK_UNCERTAIN | 4 CLOCK_UNCERTAIN |
| 7 CLOCK_FAULT | 5 CLOCK_FAULT |
| 10 EXPIRED（issue 既閉窓） | 1 INVALID_ARGUMENT |
| 11 PROFILE_MISMATCH | 6 PROFILE_MISMATCH |
| 15 CAPACITY | 7 CAPACITY |
| 16 SEQ_EXHAUSTED | 8 SEQ_EXHAUSTED |
| 17 STORAGE_FENCE | 9 STORAGE_FENCE |
| 18 CORRUPT_FENCE | 10 CORRUPT_FENCE |
| 19 COMMIT_UNKNOWN | 11 COMMIT_UNKNOWN |
| 20 STORAGE_IO | 12 STORAGE_IO |
| 21 STORAGE_CORRUPT | 10 CORRUPT_FENCE |
| 22 BUSY_REENTRY | 15 BUSY_REENTRY |
| 23 BUSY_OUTSTANDING | 14 BUSY_OUTSTANDING |
| 24 ALIAS | 16 ALIAS |
| 26 SHUTDOWN | 22 SHUTDOWN |
| 27 INVALID_STATE | 2 INVALID_STATE |
| 28 CONTRACT | 10 CORRUPT_FENCE |
| 31 RECOVER_FAIL | 20 RECOVER_FAIL |
| 32 FOREIGN_KEY | 10 CORRUPT_FENCE |
| 33 STORAGE_UNSUPPORTED | 21 STORAGE_UNSUPPORTED |
| 34 HEAD_ADVANCED | 0 OK |

### 10.9 validate → R1 status + out_error（exact）

`ninlil_radio_hal_error_t`: status, stage, reason, reserved_zero, hint[160]。

共通規則:

- 失敗時: `out_error` が non-NULL かつ alias-safe なら **status/stage/reason を書き、hint は NUL 終端短文（秘密・payload 禁止）、reserved_zero=0**。
- 成功 OK: out_error を **success 値で埋めない**（call-entry 不変、または status=OK/stage=NONE/reason=NONE の zero 拡張は **禁止** — **call-entry 不変**が唯一）。
- out_error NULL: 書き込み 0。
- validate は durable put 0。

| PCP 条件 | HAL status | stage | reason | hint token |
| --- | ---: | ---: | ---: | --- |
| OK | 0 OK | (call-entry unchanged) | (unchanged) | — |
| NULL/STRUCT/ALIAS | 5 PERMIT_ERROR | **7** PERMIT_VALIDATE | 1/39/37 | `pcp_struct` |
| UNBOUND/fence/SHUTDOWN | 5 PERMIT_ERROR | **7** PERMIT_VALIDATE | 6 or 32 | `pcp_fence` |
| CLOCK_UNCERTAIN | 4 PERMIT_DENIED | 5 TIME | 8 VALIDATOR_DENY | `pcp_clock_uncertain` |
| CLOCK_FAULT/regression | 5 PERMIT_ERROR | 5 TIME | 9 VALIDATOR_ERROR | `pcp_clock_fault` |
| NOT_BEFORE | 11 NOT_BEFORE | 5 TIME | 16 NOT_BEFORE | `pcp_not_before` |
| EXPIRED (permit window) | 12 EXPIRED | 5 TIME | 17 EXPIRED | `pcp_expired` |
| FABRICATED/PROFILE/REVOKED/ALREADY/EPOCH | 4 PERMIT_DENIED | **7** PERMIT_VALIDATE | 8 VALIDATOR_DENY | `pcp_deny` |
| BUSY_REENTRY | 9 BUSY | **7** PERMIT_VALIDATE | 13 REENTRANT | `pcp_busy` |

**SEMANTIC: validate_stage_value=7**（`NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE`）。consume stage は **8**。validate 行を 8 に書き換えてはならない。

### 10.10 consume → R1 status + out_error（exact）

| PCP 条件 | HAL status | stage | reason | hint | durable mut |
| --- | ---: | ---: | ---: | --- | --- |
| OK CONSUMED | 0 | unchanged | unchanged | — | yes FULL |
| OUT_OF_ORDER | 6 CONSUME_DENIED | 8 PERMIT_CONSUME | 41 UNCONSUMED | `pcp_ooo` | 0 |
| CLOCK_UNCERTAIN / NOT_BEFORE / BUSY pre-put | 6 CONSUME_DENIED | 8 | 41 UNCONSUMED | `pcp_retry` | 0 |
| ALREADY/REVOKED | 17 CONSUME_FENCED | 8 | 42 FENCED | `pcp_terminal` | 0 |
| FABRICATED/EPOCH | 17 CONSUME_FENCED | 8 | 42 FENCED | `pcp_fabricated` | 0 |
| bare EXPIRED head | 17 CONSUME_FENCED | 8 | 42 FENCED | `pcp_expired_head` | 0 |
| COMMIT_UNKNOWN | 17 CONSUME_FENCED | 8 | 42 FENCED | `pcp_commit_unknown` | unknown+F_s |
| IO/CORRUPT/contract | 7 CONSUME_ERROR | 8 | 11 CONSUME_ERROR | `pcp_storage` | fence |
| CLOCK_FAULT | 17 CONSUME_FENCED | 5 TIME | 42 FENCED | `pcp_clock_fault` | F_c |
| BUSY_REENTRY | 9 BUSY | 8 | 13 REENTRANT | `pcp_busy` | 0 |

**DENIED 必要十分条件:** put 未実施 ∧ 未消費確定 ∧ reason∈{UNCERTAIN, NOT_BEFORE, BUSY pre-put, OUT_OF_ORDER}。

---

## 11. Concurrency

Sole owner; reentry → BUSY_REENTRY; no heap/VLA; `object_size() <= 4096`。

---

## 12. `recover_storage` canonical scan（exact）

```text
pre: storage ops bound; handle open OK (or open first); not nested
R-S0 begin(READ_ONLY)  // shape §13
R-S1 CANONICAL_SCAN_MODE_A:
     iter_open(prefix = empty bytes_view length 0)
     // REQUIRED: empty-prefix full namespace scan
     // FORBIDDEN as sole scan: iter_open("iss/") without full-namespace pass
R-S2 for each iter_next:
     OK:
       KEY_META: len==4 && bytes=="meta"
         → value len==200; CRC; magic; schema; at most one
       KEY_ISS: len==20 && bytes[0..3]=="iss/" && bytes[4..19] in [0-9a-f]
         → value len==232; CRC; key_seq==body.permit_sequence;
            issue_generation==permit_sequence; collect seq set
       KEY_FOREIGN: else
         → reason=FOREIGN_KEY; fence_bits|=CORRUPT; F_k; goto CLEANUP_FAIL
       duplicate meta or duplicate body.seq → F_k FOREIGN/CONTRACT
     NOT_FOUND: end of iteration
     other status: map §7.8; goto CLEANUP_FAIL
R-S3 iter_close (void)  // always if iter opened
R-S4 if meta_absent && iss_count==0: rollback; return EMPTY_OK
R-S5 if meta_absent && iss_count>0: F_k; rollback; RECOVER_FAIL
R-S6 verify I1–I14 on scanned set; fail → F_k
R-S7 rollback RO; rollback fail → F_s; handle may require close+reopen before retry
R-S8 STORAGE clear only if I1–I14+CRC+no foreign:
     begin RW; fence_bits &= ~STORAGE; put meta; commit FULL
     COMMIT_UNKNOWN → retain F_s; RECOVER_FAIL
     OK → clear RAM STORAGE bit
R-S9 load meta counters/instance/bound into RAM; clear ram_validate; return OK
CLEANUP_FAIL:
     if iter open: iter_close
     rollback if txn live
     set reason; return RECOVER_FAIL / mapped status
```

**SEMANTIC markers (gate-parsed):**

- `CANONICAL_SCAN_MODE_A` + `empty-prefix full namespace scan`
- `SEMANTIC: RECOVER_SCAN_REQUIRES_EMPTY_PREFIX_FULL_NAMESPACE`
- `KEY_FOREIGN` → `FOREIGN_KEY` + fence
- `SEMANTIC: KEY_FOREIGN_MUST_FENCE` (ignore foreign is forbidden)
- `FORBIDDEN as sole scan: iter_open("iss/")`
---

## 13. Storage output shape（Foundation 整合; self-contained）

Open mapper 優先（docs/14 SH1 と同型）:

| op | OK+non-NULL out | OK+NULL out | non-OK+NULL out | non-OK+non-NULL out | unknown status |
| --- | --- | --- | --- | --- | --- |
| open | adopt handle | **REJECT_OK_NULL→CORRUPT/F_k**（adopt 禁止） SEMANTIC: OPEN_OK_NULL_REJECT | map §7.1 | **close exactly once** then F_k CORRUPT | F_k; close if handle |
| begin | adopt txn | F_k | map §7.3 | **rollback exactly once** then F_k | F_k; rollback if txn |
| iter_open | adopt iter | F_k | map §7.7 | **iter_close exactly once** then F_k | F_k; iter_close if iter |

**Zero mutation on reject:** invalid shape では table/iterator/authority durable を変更しない。
**Cleanup order:** failure+handle → close/rollback/iter_close exactly 1 → reverse しない（authority は単一 handle）。

get/put: Foundation MB 規則 — capacity/data shape 違反は CORRUPT、length 不変。

---

## 14. Acceptance vectors / mutations / docs gate

### 14.1 Host vectors（実装 PR Required）

| ID | 内容 |
| --- | --- |
| A-ADV-1..4 | expired head advance; S1→S3 |
| A-CLK-1..10 | TEMP 非 poison; OK-only full V |
| A-CLK-11 | REGRESSION fence: same-epoch 前進では解除失敗; fresh epoch で解除 |
| A-CLK-12 | PERM/ILLFORMED/UNKNOWN fence → fresh epoch 必須 |
| A-RAM-1 | validate bind seq+digest+epoch; 別 seq consume は rollback 判定に使わない |
| A-RAM-2 | recover/revoke/advance で ram_validate clear |
| A-FIFO-* | OUT_OF_ORDER / generation==seq |
| A-AIR-1 | 異 max_airtime_us の outstanding 2..8; 各 ≤ ceiling; issue OK |
| A-AIR-2 | plan airtime > ceiling → PROFILE/STRUCT deny |
| A-OPEN-1..2 | NOT_FOUND≠EMPTY; EMPTY path |
| A-PUB-1 | bind_live→publish 全 field; zero-L 拒否; COMMIT_UNKNOWN→F_s |
| A-PUB-2 | publish 前 live 未 bind → fail |
| A-REV-1 | clock fault 中でも Algorithm R 成功（clock.now 0 回） |
| A-GC-1 | eligible terminal erase; last/next 不変; I* 保持 |
| A-GC-2 | ISSUED / seq>last_consumed erase 拒否 |
| A-INV-1..3 | I14/I13/GC |
| A-STG-* | unique op×status |
| A-VAL-1 | validate get≥1 |
| A-CRC-1 | G0–G6 |
| A-API-1 | bind_* に user 引数なし; ops->user; request 無 seq |
| A-R1-1..2 | HAL order |
| A-TERM-1 | physical transmitter |

### 14.2 Machine gates（Required）

```text
python3 tools/pcp_r2_docs_gate.py check
python3 tools/pcp_r2_docs_gate.py self-test
ctest -R 'pcp_r2_|radio_usb_boundary_docs_gate'
```

| CTest / CI | 証明 |
| --- | --- |
| `pcp_r2_docs_gate` | action-line semantic + header stage 0..11 + stats 24×u64 parse (type/order/offset/width) |
| `pcp_r2_docs_gate_self_test` | **action 破壊** + **stats width** mutations: issue_ok→u8 / reserved_zero_0→u8 / consume_fenced→u8（check + consumer/static TU FAIL） |
| `pcp_r2_consumer_compile` | complete header C11 strict compile + 全24 field offsetof/width assert |
| `pcp_r2_time_sample_abi` | host LP64 offsetof |
| `pcp_r2_time_sample_abi_ilp32` | arm-none-eabi ILP32 static_assert（local） |
| **esp-idf.yml** | **必須** `xtensa-esp32s3-elf-gcc -c` + archive に `ninlil_pcp_r2_time_sample_abi_static_anchor` |

### 14.3 Docs acceptance

- [x] complete private header `src/radio/pcp_authority.h` + consumer compile
- [x] Algorithm E entry RO snapshot + E3 revoke-all + UNKNOWN 収束
- [x] recover empty-prefix full scan + FOREIGN fence
- [x] R1 out_error stage=7 validate
- [x] clock ABI offsetof C evidence LP64+ILP32
- [x] semantic mutations kill false-green
- [x] **re-review GO 禁止**

---

## 15. 関連

[05](05-security-and-compliance.md) [07](07-testing-and-quality.md) [09](09-roadmap.md) [20](20-m3-basic-esp-idf-platform-adapters.md) [21](21-m3-esp-idf-durable-storage.md) [23](23-usb-radio-boundary.md) [ADR-0003](adr/0003-radio-usb-dependency-direction.md) [ADR-0004](adr/0004-r2-durable-permit-authority.md) `radio_hal.h` `platform.h` `version.h`
