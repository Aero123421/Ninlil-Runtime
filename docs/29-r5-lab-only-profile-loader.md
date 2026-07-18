# 29. R5 LAB_ONLY Hardware/Regulatory profile loader + full permit bind

状態: **Normative for R5 host candidate** + **implementation candidate**<br>
（**R5 complete ではない** — FIELD / PRODUCTION / Japan legal / RF / HIL / R4·R7·R9 / U5 wire apply / secure radio wire 完成を主張しない）<br>
正本 ADR: [ADR-0009](adr/0009-r5-lab-only-profile-loader.md)（Accepted）<br>
依存: [05](05-security-and-compliance.md), [23 §9 / §10.2](23-usb-radio-boundary.md), [24](24-r2-physical-compliance-permit-authority.md) / R2 runtime, [25](25-u5-cell-operating-assignment.md) term/digest/generation, [27](27-r3-airtime-calculator.md) / R3, R1 `radio_hal`<br>
文書番号: **docs/29** / ADR-**0009**（R4 が docs/28 + ADR-0008 を使用 — R5 は衝突しない）

**SEMANTIC: R5_HOST_CANDIDATE_ONLY**
**SEMANTIC: LAB_ONLY_FAIL_CLOSED**
**SEMANTIC: FULL_BIND_MATRIX_ISSUE_AND_CONSUME**
**SEMANTIC: NO_JAPAN_PRODUCTION_NUMERIC_CLAIM**
**SEMANTIC: R2_DURABLE_SCHEMA1_UNCHANGED**
**SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY**
**SEMANTIC: R2_ASSIGNMENT_GENERATION_SYNC**

## 1. 位置付けと非主張

R5 は:

1. **LAB_ONLY** HardwareProfile / RegulatoryProfile の **canonical loader**（portable C、固定上限、heap/VLA/float 無し）。
2. Physical Compliance Permit の **§9.3 全 bind 項目**を **発行時・consume 時**に exact 検査する合成層。
3. R3 airtime → R2 per-permit `max_airtime_us` + profile ceiling の **handoff**。
4. R1 sole transmit-with-permit への **permit_ops 互換**接続（迂回禁止）。

**主張しない / 禁止 claims:**

- R5 complete / FIELD / PRODUCTION / deployment-approved profile
- Japan production RegulatoryProfile 数値・TELEC/ARIB 適合・legal certification
- SX1262 SPI TX / secure radio wire version / R4 / R7 / R9
- U5 ASSIGNMENT_SET wire apply complete
- HIL PASS / RF measurement / M5 complete
- public `include/ninlil` ABI
- R2 durable schema 変更（schema 1 / meta 200 / issued 232 は不変）
- independent **re-review GO**

## 2. Profile document（canonical LE fixed）

### 2.1 共通規則

- 固定長 document。truncation / oversize / trailing garbage → fail-closed。
- CRC32（poly 0xEDB88320, init/xorout 0xFFFFFFFF, refin/refout true）— R2 と同 family。
- unknown schema / magic / reserved nonzero / zero identity → fail-closed。
- approval が **LAB_ONLY 以外** → load 拒否（CANDIDATE / DEPLOYMENT_APPROVED / REVOKED / unknown すべて拒否）。
- load は **staged only**（active を上書きしない）。activate が staged→active。
- 同一 loader 内で **同一 profile_id の duplicate active** は単一 active スロット; same-id revision rollback は activate で拒否。
- active に outstanding permit（R5 registry count > 0）がある間の **in-place activate/replace** 禁止。
- revision **rollback**（active rev より小さい rev を同一 id で activate）は fail-closed（LAB_ONLY でも許可しない; 再 load は revoke/fence 後の新 generation のみ）。

### 2.2 Approval catalog（closed）

| 値 | 名前 | R5 |
| ---: | --- | --- |
| 1 | `LAB_ONLY` | **唯一受理** |
| 2 | `CANDIDATE` | 拒否 |
| 3 | `DEPLOYMENT_APPROVED` | 拒否 |
| 4 | `REVOKED` | 拒否 |
| 0, 5.. | unknown | 拒否 |

### 2.3 HardwareProfile document（128 B）

| off | sz | field |
| ---: | ---: | --- |
| 0 | 4 | magic `0x31504857` LE `'WHP1'` |
| 4 | 2 | schema = 1 |
| 6 | 2 | reserved0 = 0 |
| 8 | 16 | hardware_profile_id（nonzero） |
| 24 | 4 | hardware_profile_rev ≥ 1 |
| 28 | 16 | device_model_id（nonzero） |
| 44 | 16 | radio_sku_id（nonzero） |
| 60 | 4 | hardware_revision ≥ 1 |
| 64 | 16 | antenna_model_id（nonzero） |
| 80 | 4 | antenna_gain_mdb（LAB 合成; 法的意味なし） |
| 84 | 4 | available_bearer_count 1..4 |
| 88 | 36 | reserved1 = 0 |
| 124 | 4 | crc32 of `[0..124)` |

### 2.4 RegulatoryProfile document（160 B）

| off | sz | field |
| ---: | ---: | --- |
| 0 | 4 | magic `0x31505247` LE `'GRP1'` |
| 4 | 2 | schema = 1 |
| 6 | 1 | approval_state（**1 = LAB_ONLY only**） |
| 7 | 1 | reserved0 = 0 |
| 8 | 16 | regulatory_profile_id（nonzero） |
| 24 | 4 | regulatory_profile_rev ≥ 1 |
| 28 | 4 | region_code（LAB opaque; **Japan legal 非主張**） |
| 32 | 4 | service_category（opaque） |
| 36 | 16 | applicable_hardware_profile_id |
| 52 | 4 | applicable_hw_rev_min ≥ 1 |
| 56 | 4 | applicable_hw_rev_max ≥ min |
| 60 | 4 | channel_id_min ≥ 1 |
| 64 | 4 | channel_id_max ≥ min |
| 68 | 4 | max_airtime_ceiling_us ≥ 1（R2 ceiling 入力） |
| 72 | 4 | airtime_formula_version（must == R3 `NINLIL_AIRTIME_FORMULA_VERSION`） |
| 76 | 4 | bw_hz（must ∈ R3 closed BW set） |
| 80 | 1 | sf_min（5..12） |
| 81 | 1 | sf_max（≥ min, ≤12） |
| 82 | 1 | cr_denom_min（5..8 対応 coding_rate_denom; R1 phy と同表現） |
| 83 | 1 | cr_denom_max |
| 84 | 2 | preamble_symbols_min ≥ 6 |
| 86 | 2 | preamble_symbols_max ≥ min |
| 88 | 4 | tx_power_mdb_min |
| 92 | 4 | tx_power_mdb_max ≥ min |
| 96 | 8 | effective_not_before_ms |
| 104 | 8 | profile_expiry_ms（0 = no expiry; else > not_before） |
| 112 | 44 | reserved1 = 0 |
| 156 | 4 | crc32 of `[0..156)` |

**Schema 1 (this table):** total **160 B**; offsets 112..155 **MUST be zero**. Existing R5 LAB loaders that reject nonzero reserved remain compatible. **Schema 1 MUST NOT be used for R6 `wire_profile_id=0x11` TX.**

#### 2.4.1 RegulatoryProfile schema 2（160 B; R6 0x11 required）

| off | sz | field |
| ---: | ---: | --- |
| 0 | 4 | magic `0x31505247` LE `'GRP1'`（same as schema 1） |
| 4 | 2 | **schema = 2** |
| 6 | 1 | approval_state（1 = LAB_ONLY only） |
| 7 | 1 | reserved0 = 0 |
| 8..111 | 104 | **identical field layout to schema 1** (ids, revs, channel, PHY, airtime, effective/expiry) |
| 112 | 16 | **authority_clock_epoch_id** nonzero (R2 authority domain; text form 32-char lowercase hex) |
| 128 | 28 | reserved2 = 0 |
| 156 | 4 | crc32 of `[0..156)` |

**Accept rules:** magic GRP1; schema ∈ {1,2}; schema1 ⇒ reserved1 all zero; schema2 ⇒ authority_clock_epoch_id ≠ 0 and reserved2 zero; CRC. Unknown schema ⇒ fail-closed.
**R6 0x11:** activation **requires schema 2**. Schema 1 may load for pure LAB R5 tests only.
**R7 blocker:** production `profile_loader` currently schema1-only; schema2 decode/activate is **not implemented** in this freeze — do not claim shipped. docs/06 versioning: additive schema 2 within fixed 160 B envelope.

**Provenance:** `profile_clock_epoch_id` RAM sidecar is copied **only** from schema2 `authority_clock_epoch_id` by `ninlil_r5_private_activate_profiles_with_authority_epoch` (docs/30). Re-tagging forbidden.

**LAB 合成値の例（規範ではなく test fixture 用）:** channel 1..3、BW 125000、SF 7..9、CR denom 5..8、preamble 8..16、tx_power 0..14000 mdb、ceiling 2_000_000 µs。**Japan 920 MHz / 法的 duty を表さない。**

## 3. SiteAssignment + U5 bind fields（R5 live）

R5 active assignment（U5 wire 非実装; host bind API）:

| field | rule |
| --- | --- |
| site_assignment_id | 16B nonzero |
| site_assignment_rev | ≥ 1 |
| site_assignment_epoch | ≥ 1 |
| controller_term | ≥ 1（0 禁止; [25章](25-u5-cell-operating-assignment.md)） |
| assignment_digest | 32B（任意 bit pattern; exact match） |
| permit_bind_generation | ≥ 1 |
| transmitter_id | 16B nonzero |
| channel_id / phy | Regulatory 範囲内 |

`permit_bind_generation` ↔ R2 meta `assignment_generation`（schema1 off 156）via **`ninlil_pcp_commit_live_binding`** (full L_core+ceiling+gen single FULL txn) **exact durable sync**:

| 時点 | 動作 |
| --- | --- |
| `bind_site_assignment`（pcp already published） | `ninlil_pcp_commit_live_binding(live, gen)` full L_core+ceiling+gen（outstanding==0; strict gen rules below） |
| `bind_pcp`（assignment already bound） | same `commit_live_binding` when R2 is published; if not yet published → `INVALID_STATE` tolerated and deferred to publish/`bind_live` |
| `fence_after_revoke` | two-phase on R5 RAM object: store target=`old+1`, durable `commit_live` at target; same-object retry uses stored target; local gen/registry clear only after verified durable success. **Not process-restart durable** (R5 RAM empty after restart) |
| `activate_profiles`（assignment bound, profile change） | candidate REG must admit assignment channel+PHY (else PROFILE_DENIED RANGE, no mutation); then strict gen++ + full durable L_core rebind before swapping active |
| `issue` / `issue_with_bind` | R2 `get_assignment_generation` が plan の gen と **exact 一致**必須 |

`ninlil_pcp_set_assignment_generation` is a gen-only convenience that delegates to `commit_live_binding` keeping durable L_core; R5 rebind paths that change L_core/ceiling use `commit_live_binding` directly.

**`ninlil_pcp_commit_live_binding` generation rule (SEMANTIC: COMMIT_LIVE_SAME_GEN_EXACT_ONLY):**

- same generation → allowed **only** as exact identical live (L_core + ceiling) idempotent no-op
- any L_core / legal ceiling / live-binding change → requires **strict** generation increase (`>` current)
- same-gen different-live → `NINLIL_PCP_STRUCT` fail-closed (no durable write)

**Failure semantics (local vs durable):**

- Definite durable failure (BUSY/IO/STRUCT/…): leave local active/assignment unchanged (no local mixed active vs assignment).
- `COMMIT_UNKNOWN`: local active/assignment still unchanged; durable outcome is **unknown** until `recover_storage` / reopen. Do **not** claim mixed-free atomicity across the unknown boundary.

R2 durable に term/digest は載せない（schema1 不変; U5 ARW が term/digest 永続の正本）。

## 4. Full bind matrix（§9.3）

発行時・consume 時に **1 項目でも不一致なら拒否**。項目:

1. hardware_profile_id
2. hardware_profile_rev
3. regulatory_profile_id
4. regulatory_profile_rev
5. site_assignment_id
6. site_assignment_rev
7. site_assignment_epoch
8. controller_term
9. assignment_digest（32B）
10. permit_bind_generation
11. transmitter_id
12. channel_id
13. PHY（bandwidth_hz / SF / CR denom / preamble / tx_power_mdb / phy_flags==0）
14. frame_digest（32B）
14b. frame_digest_algorithm
15. frame_byte_length
16. max_airtime_us（R3 conservative; exact）
17. not_before_ms
18. expiry_ms
19. permit_sequence（consume: registry と durable の整合; 発行時は authority 採番）

**SEMANTIC: BIND_ITEM_SINGLE_MISMATCH_DENY** — 各項目単独不一致を host test で **issue 時**（`issue_with_bind`）と **consume 時**（`permit_validate`）の両方で証明。test-side expected は **独立定数**（production profile magic を expected 正解として再利用しない）。

**Global ALIAS zero-mutation (public APIs returning `NINLIL_R5_ALIAS`):**
- Actual geometric overlap only (owner↔const input/candidate, input↔out_error, owner↔out_error).
- Untrusted lengths use **capped geometric checks**: frame-bytes at `MAX_FRAME+1`; fixed HW/REG docs at `expected_doc_bytes+1` — pure oversize/`SIZE_MAX` is **not** ALIAS (no address-space overflow-as-overlap).
- On ALIAS: **byte-for-byte zero mutation** of full owner (stats/last_error/in_api/registry)、full const input/candidate、referenced bounded bytes、unsafe out_error canaries. No stats/last_error on ALIAS branch.
- Disjoint oversize issue plan → `STRUCT`+`REASON_STRUCT`. Fixed doc oversize → decoder `STRUCT`+`REASON_OVERSIZE`. Permit disjoint oversize/NULL+nonzero → `INVALID_ARGUMENT`+`REASON_OVERSIZE`/`STRUCT_INVALID`.
- Oversize **and** base overlapping owner/out within the capped range → ALIAS + zero mutation.

## 5. Runtime choreography

```text
init R5
load HW doc + REG doc (LAB_ONLY)
activate profiles (outstanding==0) — precedence before durable rebind/active swap:
  1. staged / outstanding / fence gates; HW↔REG applicability; LAB_ONLY
  2. identity/revision: same-id rev rollback → ROLLBACK; same id+rev with
     different full content → DUPLICATE; only full-struct equal is idempotent
  3. assignment bound: candidate REG must admit assignment channel+PHY
     (else RANGE + BIND_CHANNEL/PHY). Must not precede step 2 — same-id+rev
     content change (e.g. channel 1..3→1..1) is DUPLICATE, never RANGE
  4. assignment bound: strict gen++ + full durable L_core rebind first;
     only then swap active (definite fail preserves old active; COMMIT_UNKNOWN
     preserves local active but durable may need recover — not claimed atomic)
  5. assignment unbound: staged→active only
bind site assignment (term/digest/generation/tx/channel/phy)
  - if pcp published: commit_live full L_core+gen; else local only until publish
bind R2 live_profile from R5 (ceiling = regulatory max_airtime_ceiling_us)
publish/recover R2 as docs/24
bind_pcp (if assignment already bound and published: commit_live sync)
plan: immutable frame + R3 airtime_us
R5 issue:
  validate plan vs active profiles/assignment/ceiling
  R2 issue(request L_core + airtime + digest/len/window)
  R5 registry insert full bind (incl. term/digest/generation + seq)
R1 set_live_binding (L_core + per-permit airtime; term/digest は R5 側検査)
R1 transmit_with_permit:
  R5 permit_ops.validate → full bind + R2 validate
  R5 permit_ops.consume → full bind + R2 consume → registry remove
assignment fence (two-phase, same R5 object only):
  R2 revoke_all_outstanding
  store fence_target_generation = old+1 with fence_pending (RAM)
  durable commit_live at target; same-object retry uses stored target
  while fence_pending: bind_pcp / bind_site_assignment / activate / issue
    fail-closed (INVALID_STATE+REASON_PCP) — no PCP swap, no fence clear/retarget
    recovery = recover original PCP then fence_after_revoke retry
  only after verified durable success: registry clear + local gen = target + clear pending
  process restart: R5 RAM empty — re-fence (no persisted fence_target)
```

### 5.1 Restart / crash

- R2 recover は durable FIFO を復元する。
- R5 RAM registry は **空**。
- registry に無い outstanding seq の consume → R5 **BIND_REGISTRY_MISS** fail-closed（edge 0）。
- **R6 `0x11` の通常 restart / issued cleanup:** owner は [30章 §15.3.3](30-r6-secure-radio-wire.md) の **exported private-module drain**（storage-only recover が必要なら実行 → clockless `revoke_all` で durable outstanding 0 → clock/baseline → R5 clear/rebuild → U5 resume）を使う。`permit_bind_generation` / U5 ARW generation は **bit-exact 不変**であり、R5 が独自に `old+1` を選んではならない。
- 上記は assignment mutation ではない。実際の CellOperatingAssignment 変更時だけ [25章 §8.5](25-u5-cell-operating-assignment.md) の authenticated SET L5–L9 が新 generation を決定し、R5 はその U5-authoritative generation を bind する。既存 `fence_after_revoke` / `old+1` helper は LAB standalone assignment-fence 用であり、R6 の通常 drain には使用禁止。
- drain 後も authenticated U5 SET/RESTORE と active profile epoch bind が完了するまで TX 0。

### 5.2 R6 authority-clock profile field + activation

R6 `wire_profile_id=0x11` では RegulatoryProfile document の **`authority_clock_epoch_id[16]`**（§2.4; CRC-bound）が sole provenance である。active R5 RAM は **`profile_clock_epoch_id`** をその field から **一度だけ** copy する。host-time / Unix time は使用禁止。呼出側や W1 からの epoch/window 注入は禁止。

**Sole activation API:** `ninlil_r5_private_activate_profiles_with_authority_epoch`（docs/30 §15.3.1.1; single `in_api`）。

| check | exact |
| --- | --- |
| document | magic/CRC/LAB_ONLY; **schema=2** for R6 0x11; `authority_clock_epoch_id != 0` |
| sample | L1 accepted class-D path; fences clear; `S.epoch == authority_clock_epoch_id` |
| window | effective/expiry vs same `S.now_ms` under that epoch only |
| result | OK → `profile_clock_epoch_id := authority_clock_epoch_id`; fail → no active swap; TX 0 |

- Permit 発行は `profile_clock_epoch_id == S.epoch_id` と same-S not-before/expiry を要求する。
- authority epoch adoption 後は旧 active を invalid とし、新 document（新 epoch field + CRC）で activation が成功するまで TX 0。**旧 document への epoch 付け直し禁止。**
- process restart: R5 RAM empty → re-activate required（activation は RAM-only; durable は document bytes）。

統合契約は [ADR-0010](adr/0010-r6-secure-radio-wire.md) / ADR-0009 R6 amendment。R7 実装まで R6 TX 0。

### 5.3 R6 consume reason passthrough (typed two-catalog mapping)

When R5 `permit_ops` consume returns to R1 for R6 `wire_profile_id=0x11`:

**Catalogs:** R2 `PCP_REASON_*` ≠ R1 `NINLIL_RADIO_HAL_REASON_*`. R5 applies **typed provenance-preserving exact mapping** (docs/24 §10.10 + docs/30 §15.3.4.1). **Forbidden:** claiming numeric bit-exact preservation across catalogs (PCP 9 → HAL 16 is a **map**, not a bit copy). For 43/44/45, equal numbers are **coincidence** of separate catalog values.

| R2 PCP reason | R5 action | R1 HAL reason field |
| --- | --- | --- |
| **43** `PCP_REASON_FIFO_OUT_OF_ORDER` | map (numeric coincidence) | **43** `NINLIL_RADIO_HAL_REASON_FIFO_OUT_OF_ORDER` (R7; separate catalog) |
| **44** `PCP_REASON_CONSUME_CLOCK_UNCERTAIN` | map (numeric coincidence) | **44** `NINLIL_RADIO_HAL_REASON_CONSUME_CLOCK_UNCERTAIN` (R7) |
| **45** `PCP_REASON_CONSUME_BUSY` | map (numeric coincidence) | **45** `NINLIL_RADIO_HAL_REASON_CONSUME_BUSY` (R7) |
| **9** `PCP_REASON_NOT_BEFORE` | **map** (not bit-exact) | **16** `NINLIL_RADIO_HAL_REASON_NOT_BEFORE` (not a PCP code) |

No bare `NINLIL_R5_PCP` collapse; no hint-only discrimination. Sample `PCP_REASON_CLOCK_UNCERTAIN=6` is not a consume path code. Current production HAL 41/42 collapse is non-conformant for R6 TX until R7.

## 6. Packaging

| 成果物 | tests-ON | tests-OFF private archive | ESP component |
| --- | --- | --- | --- |
| `profile_loader.c` | yes | **yes（production source）** | yes |
| tests / gate / oracle | yes | **no** | no |
| public include/ninlil | no | no | no |

## 7. Testing / gate

| Gate | 内容 |
| --- | --- |
| `profile_r5` CTest | LAB_ONLY load; non-LAB deny; full bind mismatch matrix; R3 handoff; R2 issue/consume; restart registry miss; fence/generation; structural negatives |
| `profile_r5_gate` | semantic anchors + mutation self-test（loader 削除 / LAB 以外許可 / bind 項目削除 / FIELD 主張） |
| existing R1/R2/R3 | **回帰 green 必須**（durable layout / CRC / FIFO 非破壊） |

## 8. Acceptance（R5 candidate）

- [x] LAB_ONLY only; other approval fail-closed
- [x] no Japan production numeric claim
- [x] full §9.3 bind matrix issue+consume single-mismatch tests
- [x] R3 airtime handoff + ceiling
- [x] R2 durable schema1 unchanged
- [x] R1 sole edge not bypassed
- [x] private packaging; tests-OFF clean
- [x] honest nonclaims in docs/CHANGELOG/roadmap

## 9. 関連
