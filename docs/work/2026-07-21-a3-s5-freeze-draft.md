# 素案: §18.16 Normative D3-S5a freeze（DSW2_SUPERSEDE_CHAIN / successor chain bounded walk）

状態: **Draft rev6 / docs-only 素案（docs/17 本体未変更; 採択時に移植）**
版: **rev6**（2026-07-21; r5 レビュー NO-GO P0=0 P1=1 反映）
作成: 2026-07-21
Decision identifier: **D3-S5a**
移植先: `docs/17-foundation-domain-store.md` §18.16（§18.15 の次）

## レビュー履歴

| 版 | 日付 | 結果 | 摘要 |
| --- | --- | --- | --- |
| rev1 | 2026-07-21 | **NO-GO** P0=4 P1=8 P2=2 | 初稿。TBD 7 件未確定、Mode36 過剰、u16 bound、cost 過少 |
| rev2 | 2026-07-21 | **NO-GO** P0=1 P1=2 | r1 全所見反映。TBD 確定、k₅=1、u64、canonical digest、cost 修正 |
| rev3 | 2026-07-21 | **NO-GO** P0=1 P1=1 | r2 反映。next-hop digest pin、lex order、SHA separator、S6 ledger |
| rev4 | 2026-07-21 | **NO-GO** P0=0 P1=3 | r3 反映。hop_witness_digest 別 pin、separator 25B、worked example |
| rev5 | 2026-07-21 | **NO-GO** P0=0 P1=1 | r4 全 P1 反映。prev_hop 代入元修正、positive #1 M=2、worked example W2 carrier 追記 |
| rev6 | 2026-07-21 | — | r5 P1 反映。`header_state` を substep 0 で pin（successor witness_state）、substep 3 分岐前提として保持 |

---

### 18.16 Normative D3-S5a freeze（DSW2_SUPERSEDE_CHAIN / successor chain bounded walk）

**Decision identifier: D3-S5a。** 本節は D3-S0 / S1a / S2a / S3a（§18.14）/ **S4a（§18.15）** を **上書きせず**、§10.1 **`DSW2_SUPERSEDE_CHAIN`** の **docs-only Normative freeze** を追加する。§18.15（S4: **949/960**, outer **10880**）は **origin/main と byte-equivalent に保持**。**docs only**（code/tests/CMake/JSON/ADR 0）。implementation / D3 / Stage5 / D4 / public Runtime / ESP / hardware **pending**。private symbol 存在 **未 claim**。

**Design choice:** 1 session = 1 mode = **Mode35**; **k₅=1**; single `READ_ONLY` txn; **single 4096**; fixed S5 context; no full-ID set; no heap/VLA/second 4096/two-txn list-prove。**retire/cleanup physical erase truth → S6; mutation → D4**。Mode35 は SUPERSEDED header ごとに successor exact_get + successor manifest SUPERSEDE_WITNESS entry full-M 検証 + **bounded chain walk（cycle detection）** を行う。各 get 後の cursor progress を本節だけで閉じる。

**ACTIVE successor-zero は S5 scope 外:** ACTIVE header の `successor_witness_digest==zero` は §10.1 の header-local same-record invariant であり、§18.6 が D1/D2-S3 所有とする。S5 は cross-row bounded walk だけを所有し、header-local invariant を再発明しない。

**Composite key rule:** witness header の complete key は、その時点で実バイトとして pin 済みの `witness_digest`（composite identity 32 bytes）から **forward rebuild** する（root[8] + family6 + subtype `7f` + identity-kind COMPOSITE + identity bytes）。`KEY_DIGEST` から raw identity を reverse することは **禁止**。

**S4 deferred authority との関係:** S4（§18.15）が `S5_REQUIRED` / `S5_AND_S6_REQUIRED` disposition を finalize したとき、D3 success への昇格は本 S5 の successful composition を要求する。S5 は S4 の deferred bit を **消費する側** であり、S4 disposition を再発行・上書きしない。S5 単独の local complete は S4 deferred を自動的に解決しない（higher D3 composition accumulator が両 slice の disposition を合成する）。

**Digest collision / raw bijection:** S5 は SHA-256 collision resistance を **assumption** として依存する。D1 が証明できるのは「返された key/body raw が同じ composite digest を再計算する」ことまでであり、真の SHA-256 collision を検出できない。S5 は各 hop で successor header の D1-valid complete key と body `witness_digest` の **raw/key bijection** を独立に検証し、digest equality だけで同一性を決めない。Collision resistance が破られた場合、本 freeze の保証は SHA-256 のそれを超えない。

#### 18.16.0 Value lifetime / pin discipline

| Rule | Exact |
| --- | --- |
| Borrow | `value[4096]` は **直近 1 回** successful `exact_get` / iter value のみ valid |
| Invalidate | 次の `exact_get` / value 供給 / cleanup で **即 invalid** |
| Pin before overwrite | 後続 get 後に必要な digest / complete key bytes / manifest framing / canonical old digest は **get 前**に fixed context へ copy |
| Forbidden | invalid value を VALUE_DIGEST / body raw rebuild / entry comparison / canonical SHA 入力に使う |

#### 18.16.1 Snapshot-only DSW2 scope

| In scope | Out |
| --- | --- |
| SUPERSEDED successor chain bounded walk / cycle / missing successor | S6 retire/cleanup physical erase truth |
| successor manifest SUPERSEDE_WITNESS entry full-M exact 検証（canonical old/new header digest + state transition） | D4 commits / mutation |
| self-reference / cycle / missing successor / re-supersede detection | incoming predecessor reference walk（S6） |
| RETIRED successor 到達時の manifest proof + S6 handoff | RETIRED retirement eligibility proof（S6） |
| finalize / evaluator-off / incomplete-mask / quota=1 substep progress | ACTIVE successor-zero（D1/D2-S3 header-local） |
| | public Runtime |

#### 18.16.2 Closed mode 35

| Mode | Carrier | Core |
| ---: | --- | --- |
| **35** | every SUPERSEDED WITNESS_HEADER | bounded successor chain walk: successor exact_get + manifest SUPERSEDE_WITNESS entry full-M 検証 + cycle bound + RETIRED handoff |

**k₅=1** は D3-S5 **complete** の closed mode 集合（**1 self-contained session**）。S1 exact-1 modes 1..20、S2 modes 21..26、S3 modes 27..30、S4 modes 31..34 は維持。S5 mode は **35** だけ。36..255 は invalid。

#### 18.16.3 Same-txn phase machine

```text
IDLE → BASELINE (D2 once; count witness headers → walk_bound u64)
  → close sole iterator; reopen zero-prefix in same txn
  → Mode 35:
      (SELECT_HEADER → install SUPERSEDED header; pin canonical old digest
         → CHAIN_HOP loop:
            (substep 0: successor exact_get → verify existence/state/raw bijection
             substep 1..2: MANIFEST_ENTRY_PROOF: stream successor manifest chunks
               full-M; find SUPERSEDE_WITNESS entry matching predecessor key exact 1
               verify canonical old/new digests + framing + SHA
             substep 3: advance hop:
               prev_hop := current; current := successor;
               if successor ACTIVE → substep 4 WALK_CLOSE
               if successor SUPERSEDED → substep 0 next hop
               if successor RETIRED → manifest proof complete → S6_REQUIRED set → WALK_CLOSE)*
         → WALK_CLOSE: chain valid or CYCLE/MISSING corrupt
         → preserve last_carrier_key; next SELECT)*
   → COMPLETE | FAILED | mid-drive yield (not terminal)
```

**BASELINE:** D2 structural scan と同じ single full-domain iterator walk。witness header（family6 subtype `7f`）を **checked-u64** count し `walk_bound` に install する。`walk_bound == 0` の snapshot は witness header 不在であり、carrier 0 で vacuous complete。BASELINE 完了後、sole iterator を close し、same txn で zero-prefix iterator を reopen する（§18.3 S2a/S3a/S4a と同型の sequential zero-prefix reopen）。

**SELECT_HEADER:** reopen した iterator を `last_carrier_key` の strictly after から resume し、次の SUPERSEDED WITNESS_HEADER を select。D1-valid SUPERSEDED header を install:
- `witness_digest` := header composite identity（body から; key/body raw bijection 検証済み）
- `successor_witness_digest` := body field（non-zero 必須; zero は **MISSING_SUCCESSOR CORRUPT**）
- `predecessor_complete_key` := header complete key bytes（live value から copy）
- `expected_entry_new_digest` := `VALUE_DIGEST(live SUPERSEDED complete value)`
- **canonical old digest 導出**（§18.16.5.1）
- `record_revision` == 2 必須（§18.16.5.1）
- `last_carrier_key` := header complete key（iterator position）

**Substep 0 next-hop pinning（successor value live 中に必須）:** successor header を exact_get した後、その value が live の間に次を pin する:
- **`hop_witness_digest` := successor の composite identity**（= exact_get に使った identity; chunk key 構築・owner 要求に使用。`successor_witness_digest` とは **別 pin**）
- **`header_state` := decoded successor `witness_state`**（1 ACTIVE / 2 SUPERSEDED / 3 RETIRED）。**substep 3 完了まで保持**（quota=1 を含む call-spanning manifest proof 後に分岐を再現するため）
- successor framing: `member_count`, `chunk_count`, `expected_manifest_digest`
- `successor_witness_digest` := successor body の successor field（**次 hop の get 用**; ACTIVE なら zero）
- **`header_state == 2`（SUPERSEDED）の場合のみ:**
  - `next_old_digest` := successor の canonical ACTIVE 合成（§18.16.5.1; incremental SHA）
  - `next_new_digest` := `VALUE_DIGEST(successor complete value)`
- **`header_state == 1`（ACTIVE）または `header_state == 3`（RETIRED）の場合:** `next_old_digest` / `next_new_digest` は計算しない（chain 停止のため不要）

pin 完了後、successor value は chunk get で失効してよい。

**`hop_witness_digest` と `successor_witness_digest` の区別（必須）:**
- `hop_witness_digest` = 「今 manifest を検証している successor header 自身の identity」。substep 1-2 の chunk key 構築（`chunk_key(hop_witness_digest, floor(i/8))`）と owner 照合に使う。
- `successor_witness_digest` = 「その successor header の body に記録された次 hop の target」。substep 3 promotion 後の次 substep 0 で exact_get に使う。
- 両者は **同時に live** であり、alias / 上書きは **禁止**。

**Hop promotion（substep 3 → next hop substep 0）:** digest shift は exact:
```text
prev_hop_witness_digest := witness_digest        # OLD current (W1) becomes prev
witness_digest := hop_witness_digest             # W2 becomes new current
predecessor_complete_key := forward-rebuild from hop_witness_digest (W2's key)
expected_entry_old_digest := next_old_digest     # W2's canonical old (pinned at substep 0)
expected_entry_new_digest := next_new_digest     # W2's live new (pinned at substep 0)
walk_steps := walk_steps + 1
# reset for next manifest stream:
streamed_members := 0; entry_found := 0
SHA state := domain separator init (§18.16.6 rule 10)
prev_member_key_len := 0
# successor_witness_digest (= W3) is already pinned from previous substep 0; unchanged
# hop_witness_digest will be overwritten at NEXT substep 0 with W3's identity
```
`prev_hop_witness_digest` には **旧 `witness_digest`**（上書き前の current）を代入する。`hop_witness_digest` を代入してはならない（両方が新 current になると immediate-bounce 検出が破綻する）。`origin_witness_digest` は SELECT 時から不変。`next_old_digest` / `next_new_digest` は substep 0 で successor live 中に pin 済みであり、substep 3 で successor value を再取得しない（**re-get 禁止**; get budget 不変）。

#### 18.16.4 PASS_INTERNAL / drive quota + substep progress

| Item | Contract |
| --- | --- |
| `drive_get_quota` | each drive/advance: default **32**; legal **1..256**（**1 is legal**） |
| `drive_gets_used` | +1 per S5 `exact_get` attempt |
| Yield | used==quota mid work → OPEN, `flags.need_resume=1`, **no sticky**; preserve all pins/cursors/substeps |
| Resume | refill quota; continue **same substep cursor** — **must not re-issue a completed get** |

**`walk_substep`（Mode35; per hop）:**

| Value | Meaning | Next action | On success |
| ---: | --- | --- | --- |
| **0** | need successor header get | forward-build successor key from `successor_witness_digest` into `peer_key`; `exact_get`; verify existence + state + raw/key bijection; **pin `header_state` := decoded successor witness_state**; pin successor framing（M, C, manifest_digest）; pin `successor_witness_digest` from body; **if `header_state==2`: compute + pin `next_old_digest` / `next_new_digest` while live**（§18.16.3）; init SHA domain separator | → **1**（successor value may die; `header_state` retained） |
| **1** | manifest entry proof: chunk re-get for `streamed_members` | forward-build chunk key from **`hop_witness_digest`** + `floor(streamed_members/8)`; `exact_get(chunk)` | → **2**（chunk live） |
| **2** | inspect entry at `streamed_members % 8`; SHA feed（`i%8==0` only）; if SUPERSEDE_WITNESS + key match → verify old/new digests + require `entry_found==0`（duplicate reject）→ set `entry_found=1`; advance `streamed_members` | if `streamed_members == M` → **3**; else → **1**（next member） | |
| **3** | full-M close: require `entry_found==1` + framing exact + final SHA == `expected_manifest_digest`; then branch on **pinned `header_state`** | `walk_steps++`; if `header_state==1`（ACTIVE）→ **4**; if `header_state==2`（SUPERSEDED）→ promote（§18.16.3）→ **0**; if `header_state==3`（RETIRED）→ set `binding_complete_mask.bit5` → **4** | |
| **4** | WALK_CLOSE: chain walk complete for this origin | no get; header complete → next SELECT | |

**Forbidden with quota=1:** looping substep 1 forever（re-getting same chunk without advancing `streamed_members`）。Each successful get **must** advance `walk_substep` or `streamed_members` or `walk_steps`。

Values 5..255 are invalid。

#### 18.16.5 Successor chain walk / cycle detection

**Bounded walk contract（§18.5 category E）:**

| Rule | Exact |
| --- | --- |
| Origin | Mode35 SELECT_HEADER で install した SUPERSEDED header の `witness_digest` を `origin_witness_digest` へ pin |
| Hop | 各 hop で current header の `successor_witness_digest` から successor を exact_get |
| Bound | `walk_steps`（u64）が `walk_bound`（u64; = baseline で checked count した witness header 総数）に **達したら**（≥） **CYCLE CORRUPT** |
| Self-reference | successor_witness_digest == own witness_digest → **SELF_REFERENCE CORRUPT**（substep 0 で検出） |
| Origin cycle | successor_witness_digest == `origin_witness_digest` → **CYCLE CORRUPT** |
| Immediate bounce | successor_witness_digest == `prev_hop_witness_digest`（直前 hop と同じ）→ **CYCLE CORRUPT** |
| ACTIVE terminus | successor state == ACTIVE → chain valid; WALK_CLOSE |
| SUPERSEDED continuation | successor state == SUPERSEDED → 次の hop へ進み、その successor manifest も full-M 検証 |
| RETIRED successor | substep 0 で successor header + manifest entry を **full-M で証明した後**、`binding_complete_mask.bit5=s6_required_seen` を set し WALK_CLOSE。RETIRED node 自身の successor suffix・retirement eligibility・incoming reference・partial chunk truth は **S6 へ明示移管**。manifest proof 前の停止は **禁止** |
| Missing successor | exact_get ABSENT → **MISSING_SUCCESSOR CORRUPT** |
| Invalid successor state | successor state が ACTIVE/SUPERSEDED/RETIRED 以外（D1-invalid / future）→ normal D2 precedence; unsupported only under recognizable-future rule, otherwise **CORRUPT** |

**Walk は全 header 集合を RAM へ置かない。** 起点ごとの bounded walk と fresh exact_get だけで行う（§10.1）。visited set / full-ID set / hash table は **禁止**。

##### 18.16.5.1 Canonical old ACTIVE digest 導出（P0-1 確定）

SUPERSEDED carrier は common `record_revision == 2` を **必須** とする（revision ≠ 2 は **CORRUPT**; §10.1: ACTIVE creation revision=1, ACTIVE→SUPERSEDED replacement で exactly +1）。

`expected_entry_old_digest`（SUPERSEDE_WITNESS entry の `old_value_digest` 期待値）は、live SUPERSEDED complete `NLR1` value から **canonical 変換** で導出する:

1. Live value を decode（D1-valid 済み）。body 内の `operation_identity` length を含む exact field offsets を確定。
2. 以下の **3 field だけ** を canonical 値へ置換し、他は byte-equivalent:
   - common header `record_revision`: 2 → **1**（u64 BE）
   - body `witness_state`: 2 → **1**（u16 BE; ACTIVE）
   - body `successor_witness_digest`: non-zero → **zero[32]**
3. `payload_length` は不変（field size 不変）。NLR1 envelope magic/type/version 不変。
4. 置換後 byte 列の **CRC32C** を再計算（§12 6.2: Castagnoli, checksum field 除く先頭〜payload 末尾）。
5. `magic || type || version || payload_length || modified_payload || new_CRC` の complete NLR1 encoded bytes へ **SHA-256** を適用。
6. 結果が `expected_entry_old_digest`。

**Second 4096 buffer 禁止:** canonical SHA は incremental feed で行う。live value の byte 列を offset 順に SHA/CRC へ投入し、3 field の offset 位置で canonical byte を substitute する。field offset は D1 decoded view から確定済み。

`expected_entry_new_digest` は `VALUE_DIGEST(live SUPERSEDED complete value)`（trivial; live value 全体の SHA-256）。

##### 18.16.5.2 Re-supersede detection（P0-2 確定）

`SUPERSEDE_WITNESS` entry に successor field は **存在しない**（§10.1 entry encoding: record_role / action / key / old_present / new_present / prior_head / old_value_digest / new_value_digest のみ）。存在しない field の比較は **禁止**。

Re-supersede / successor identity の束縛は以下の **組合せ** で検出する:

1. `record_revision == 2`（exactly once superseded）
2. `expected_entry_old_digest`（canonical ACTIVE 合成）== entry `old_value_digest`
3. `expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST）== entry `new_value_digest`
4. target entry **exact 1 件**（duplicate reject）
5. successor header の `witness_digest` == predecessor body `successor_witness_digest`（raw/key bijection）

この組合せにより、predecessor が記録した successor identity と実際に取得した successor header の manifest owner が一致することを証明する。異なる successor への差し替え（別successor）は条件 5 で検出される。

#### 18.16.6 SUPERSEDE_WITNESS manifest entry full-M verification

各 hop で successor header の manifest を **full-M** stream し、predecessor の SUPERSEDE_WITNESS entry を exact 検証する（§18.15.3 と同等の厳密度）:

1. Successor header value が live の間に `member_count=M`, `chunk_count=C`, `manifest_digest` を pin。`1 ≤ M ≤ 256`; `C = ceil(M/8)` and `1 ≤ C ≤ 32`。
2. `streamed_members = 0`, `entry_found = 0`, `prev_member_key_len = 0` から開始。
3. 各 ordinal `i`（0..M-1）に対し `chunk_key(hop_witness_digest, floor(i/8))` を forward-build し exact_get。
4. 返された chunk の `witness_digest`, `chunk_index`, `chunk_count` が installed successor header / exact `floor(i/8)` / `C` と一致しなければ CORRUPT。
5. **非末尾 chunk は exact 8 entries、末尾 chunk は exact `M - 8*(C-1)` entries**（1..8）。entry count 不一致は CORRUPT。
6. **Strict unsigned-byte lex order（§18.15.3 同型）:** 全 M entries は key unsigned-byte lexicographic 昇順でなければならない。`prev_member_key` は chunk 境界をまたいで保持する。current entry key ≤ `prev_member_key` は **ORDER_CORRUPT**（equality = duplicate, decreasing = out-of-order）。`prev_member_key` は各 entry 検査後に更新。
7. Entry slot `i%8` を検査: `action == 4`（SUPERSEDE_WITNESS）かつ `key_bytes == predecessor_complete_key`（byte-exact, `key_length` 含む）の entry を探す。
8. **Target entry duplicate reject:** `entry_found == 1` の状態で 2 件目の match を発見したら **DUPLICATE_ENTRY CORRUPT**。
9. 該当 entry が見つかったら（`entry_found == 0` の場合のみ）:
   - `old_present == 1`, `new_present == 1`
   - `old_value_digest == expected_entry_old_digest`（canonical ACTIVE 合成; §18.16.5.1）
   - `new_value_digest == expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST）
   - `record_role` high byte == family6（`0x06`）, low byte == subtype `7f`
   - `prior_head_witness_digest == zero`（SUPERSEDE_WITNESS は witness metadata member; §10.1）
   - `entry_found := 1`
10. **SHA domain separator + feed:** manifest SHA は §5.1 の exact domain-separated formula: `SHA-256(ASCII("NINLIL-DOMAIN-MANIFEST-V1") || chunk_body_0 || ... || chunk_body_n)`。**substep 0 の pin 完了時に SHA state を初期化し、domain separator `ASCII("NINLIL-DOMAIN-MANIFEST-V1")`（exact 25 bytes）を最初の feed として投入する**（exact transition; chunk body 投入前）。`i%8 == 0` のときだけ exact encoded chunk body を SHA へ投入（同一 chunk の within-chunk re-get は 8 ordinal 連続で合法だが、SHA 投入は chunk 境界の一度だけ）。
11. **Full-M close:** `streamed_members == M` に達したとき:
    - `entry_found == 1` 必須（0 は **MISSING_ENTRY CORRUPT**）
    - implied visited chunk count == C
    - final SHA == `expected_manifest_digest`（不一致は **MANIFEST_SHA CORRUPT**）
12. Within-chunk re-get（同じ chunk を 8 ordinal 連続で再取得）は **required/合法**（S4 §18.15.3 と同型）。A returned-index duplicate is corruption only when it repeats across a chunk boundary where `floor(i/8)` advanced, when an iterator supplies a duplicate complete chunk row/key, or when the returned index differs from the current requested `floor(i/8)`。

All checks use D1-valid decoded rows。A local D1 failure remains D2 corruption and is not reclassified by S5。

#### 18.16.7 Exact get-budget table

| Situation | exact_gets |
| --- | --- |
| **35** per hop（successor header get） | **1** |
| **35** per hop（manifest entry full-M proof） | **M_successor** chunk re-gets |
| **35** per origin total | **Σ_hops (1 + M_hop)**; hops ≤ walk_bound |
| **35** session total（all SUPERSEDED origins） | **Σ_origins Σ_hops (1 + M_hop)** |

#### 18.16.8 Precedence / finalize gates

| Gate | Exact |
| --- | --- |
| Traversal complete | phase COMPLETE + Mode35 required masks + no sticky corruption + INTERNAL done（or vacuous-empty carrier set） |
| COMPLETE_READY | traversal complete + `binding_complete_mask.bit5==0`; set `flags.bit3=1` |
| DEFERRED_READY | traversal complete + `binding_complete_mask.bit5==1`（RETIRED successor encountered; S6 correlation pending）; `flags.bit3` **must remain 0** |
| Finalize result | COMPLETE_READY and DEFERRED_READY both sample the private disposition, perform normal cleanup, publish one complete private result, return `NINLIL_OK`; deferred disposition is **not D3 success** until S6 composition succeeds |
| Incomplete masks / mid-yield | finalize → INVALID_STATE Port 0; no cleanup |
| Evaluator-off | baseline candidate only; both READY shapes forbidden; frozen D2 unsupported/corrupt aggregate path; publishes `d3s5_disposition_present=0`, `d3s5_disposition=0` only when cleanup succeeds |
| Sticky terminal | further d3s5_drive → INVALID_STATE Port 0 |
| Cleanup | iter_close → rollback → optional fence → DONE |

**Precedence order:** D2/local decode CORRUPT > MISSING_SUCCESSOR / CYCLE / SELF_REFERENCE / MISSING_ENTRY / DUPLICATE_ENTRY / ORDER_CORRUPT / MANIFEST_SHA / revision CORRUPT > `S6_REQUIRED` deferred > local valid。Deferred bit は既存 corruption を suppress しない。

**Required exact masks by session（Mode35 only）:**

| Shape | Required |
| --- | --- |
| Mode35 normal complete | `count_complete_mask.bit0==1`（all SUPERSEDED headers walked）; `binding_complete_mask.bit0==1`（chain walk binding complete）; `binding_complete_mask.bit5==0` |
| Mode35 with RETIRED handoff | same + `binding_complete_mask.bit5==1`（S6 deferred） |
| Vacuous（walk_bound==0, no SUPERSEDED carrier） | `count_complete_mask.bit0==1` + `binding_complete_mask.bit0==1`（vacuous-empty inventory proves both）; bit5==0 |
| Invalid extra bits | `count_complete_mask` bits1..7 set, or `binding_complete_mask` bits1..4/6/7 set → **INVALID_STATE** |

**Private finalize disposition:**

- **0 LOCAL_COMPLETE**（bit5==0）
- **2 S6_REQUIRED**（bit5==1; RETIRED successor encountered）

S5 は `S5_REQUIRED`（disposition 1）を **生成しない**（S5 自身が successor proof であるため）。S5 が生成し得るのは 0 と 2 だけ。Invalid enum/MBZ/mode-bit shape or sticky corruption is never converted to a deferred result。

**Closed private result carrier（implementation-required）:** append the following exact declaration-order fields after the D3-S4 carrier bytes（`d3s4_disposition` at offset 53）in `ninlil_domain_scan_result_t`:

```c
uint8_t d3s5_disposition_present; /* declaration offset 54; exact 0 or 1 */
uint8_t d3s5_disposition;         /* declaration offset 55; present=1: exact 0 or 2; present=0: exact 0 */
```

`present=1, disposition=0` is LOCAL_COMPLETE。`present=1, disposition=2` is S6_REQUIRED。`present=0` with non-zero disposition, `present>1`, `present=1` with disposition==1 or disposition>2 is invalid and may never be published。Higher D3 composition accepts a disposition **only when finalize returned `NINLIL_OK` and `d3s5_disposition_present==1`**。

**Private-result size/stack accounting:** S4 append 後 host layout は named bytes through offset 53, natural `sizeof=56`, alignment 8。S5 の 2 bytes は declaration offsets **54/55** に append し、host tail-padding 内で `sizeof` は **56** を維持（S4 と同型）。Target ABI padding は仮定しない: implementation must `_Static_assert(sizeof(ninlil_domain_scan_result_t) <= 64)` and record host plus ESP32-S3 target `sizeof`/alignment in the implementation oracle。Commit-style candidate publication adds at most **64 bytes** of finalize function stack; no record/value buffer is placed there。This result is caller output/temporary, not part of the S5 context or co-resident D3 arena, so S5 **651/656**, outer **11536**, and packed aggregate arithmetic remain unchanged。

**Output/cleanup mutation matrix（whole `ninlil_domain_scan_result_t` as output unit）:**

| Call/path | Port calls | `out_result` | S5 context/session |
| --- | ---: | --- | --- |
| finalize, evaluator-on READY, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=1`, disposition exact 0 or 2; return `NINLIL_OK` | sample disposition to scalar before cleanup; after publish, zero entire S5 context and finish DONE |
| finalize, evaluator-off frozen aggregate, cleanup success | cleanup tree | publish one fully initialized temporary result; `present=0`, disposition=0; return frozen aggregate status | after publish, zero entire S5 context and finish DONE |
| finalize from FAILED, cleanup success | cleanup tree | publish diagnostics with `present=0`, disposition=0 and the sticky non-OK status | after publish, zero entire S5 context and finish DONE |
| finalize, any cleanup failure | cleanup tree/fence | **all bytes unchanged** from caller poison; sampled disposition discarded | zero entire S5 context after Port cleanup; finish terminal |
| abort from legal OPEN/EXHAUSTED/FAILED | cleanup tree/fence | **all bytes unchanged** | zero entire S5 context after Port cleanup; finish terminal DONE |
| NULL, output alias, invalid state, incomplete masks/mid-yield, invalid enum/MBZ | **0** | **all bytes unchanged** | session/context/workspace unchanged |

Prevalidation checks all required pointers/state/shape and requires the complete result range to be disjoint from the session, bound workspace, bound ops object, bound handle slot, and bound S5 context **before** any Port call, output write, or cleanup。Exact order: **derive/sample scalar disposition → Port cleanup outcome → build/publish complete output → zero S5 context**。

#### 18.16.9 Honest cost

| Mode | Baseline | Internal | Session |
| ---: | --- | --- | --- |
| 35 | **Θ(N)** | **Θ(N + Σ_origins Σ_hops (1 + M_hop))** | **Θ(2N + W_chain)** |

**Worst-case chain topology:** 単一 long chain of length L（W1→W2→…→WL ACTIVE, L-1 SUPERSEDED origins）。各 origin W_i は hop i→i+1, i+1→i+2, …, L-1→L を walk し、各 hop j で successor manifest M_j を full-M stream する。Hop j は j 件の origin（W1..Wj）から再走査されるため:

**Total = Σ_{j=1}^{L-1} j·(1 + M_{j+1})**

一様 M では **Θ(L²·(1 + M_avg))**。これは **honest quadratic-class wall time**（§18.5 honest cost 規則）であり、memory は fixed（full-ID set なし）。

**False O(N) claim 禁止:** S5 の chain walk cost を「O(N) one-pass」や「Θ(L² + L·M_avg)」と偽らない。各 manifest が複数 origin から再走査される事実を隠してはならない。

D3-S5 complete = **1 × baseline + every internal walk/manifest stream**。

#### 18.16.10 Fixed S5 context layout（sizeof **651** / align 1 / ceiling **656**）

全 physical field は `uint8_t` scalar/array。multi-byte 値は big-endian byte array。`alignof == 1` と exact sizeof を `_Static_assert` で検証する。Natural alignment padding は存在しない。

| Offsets | Size | Field |
| ---: | ---: | --- |
| 0..44 | 45 | `last_carrier_key` |
| 45 | 1 | `last_carrier_key_len` |
| 46..77 | 32 | `witness_digest`（current hop header composite identity; cycle detection 用） |
| 78..109 | 32 | `origin_witness_digest`（walk origin; cycle detection） |
| 110..141 | 32 | `successor_witness_digest`（current header body の次 hop target; substep 0 get 用） |
| 142..173 | 32 | **`hop_witness_digest`**（現在 manifest を検証中の successor 自身の identity; chunk key 構築・owner 照合用。`successor_witness_digest` と同時 live・別 pin） |
| 174..205 | 32 | `prev_hop_witness_digest`（immediate previous hop; bounce detection） |
| 206..237 | 32 | `expected_manifest_digest`（successor's manifest digest for SHA） |
| 238..269 | 32 | `expected_entry_old_digest`（canonical ACTIVE 合成; §18.16.5.1） |
| 270..301 | 32 | `expected_entry_new_digest`（live SUPERSEDED VALUE_DIGEST） |
| 302..333 | 32 | `next_old_digest`（successor's canonical ACTIVE; pinned at substep 0 while successor live; next hop 用） |
| 334..365 | 32 | `next_new_digest`（successor's live VALUE_DIGEST; pinned at substep 0; next hop 用） |
| 366..410 | 45 | `predecessor_complete_key`（current origin header's complete key for entry matching） |
| 411 | 1 | `predecessor_complete_key_len` |
| 412..456 | 45 | `peer_key`（successor header get / chunk request） |
| 457 | 1 | `peer_key_len` |
| 458..502 | 45 | `prev_member_key`（manifest lex order check; chunk 境界をまたぐ） |
| 503 | 1 | `prev_member_key_len` |
| 504..535 | 32 | `sha_state` |
| 536..543 | 8 | `sha_bitcount` |
| 544..607 | 64 | `sha_block` |
| 608 | 1 | `sha_block_len` |
| 609..610 | 2 | `member_count` u16 BE（successor's M） |
| 611..612 | 2 | `chunk_count` u16 BE（successor's C） |
| 613..614 | 2 | `streamed_members` u16 BE（manifest entry proof ordinal） |
| 615..622 | 8 | `walk_steps` **u64 BE** |
| 623..630 | 8 | `walk_bound` **u64 BE**（= baseline witness header checked count） |
| 631..632 | 2 | `drive_get_quota` u16 BE |
| 633..634 | 2 | `drive_gets_used` u16 BE |
| 635 | 1 | `phase` |
| 636 | 1 | `pass_kind` |
| 637 | 1 | `focus_mode` |
| 638 | 1 | `flags` |
| 639 | 1 | `count_complete_mask` |
| 640 | 1 | `binding_complete_mask` |
| 641 | 1 | `walk_substep` |
| 642 | 1 | `header_state`（current hop: 0 none / 1 ACTIVE / 2 SUPERSEDED / 3 RETIRED） |
| 643 | 1 | `entry_found`（0/1; SUPERSEDE_WITNESS entry located） |
| 644..645 | 2 | `entry_key_length` u16 BE |
| 646..647 | 2 | `entry_record_role` u16 BE |
| 648..650 | 3 | reserved MBZ（exact 0） |
| **Σ** | **651** | |
| ceiling | **656** | headroom **5** |

**flags:** bit0 baseline_done; bit1 focus_live; bit2 bind_phase_active; bit3 complete_ready; bit4 need_resume; bit5 header_installed; bit6 manifest_sha_open; **bit7 MBZ**（S5 は `S5_REQUIRED` を生成しないため不要; 確定）。

**Exact state-byte / bit ownership:**

| Byte | Bits / values |
| --- | --- |
| `phase` | 0 IDLE; 1 BASELINE; 2 SELECT; 3 CHAIN_HOP; 4 MANIFEST_PROOF; 5 WALK_CLOSE; 6 COMPLETE; 7 FAILED; 8..255 invalid |
| `pass_kind` | 0 PASS_BASELINE; 1 PASS_INTERNAL; 2..255 invalid |
| `focus_mode` | 0 only before begin / after cleanup; 35 only while active; 1..34 and 36..255 invalid |
| `flags` | bits0..6 as above; bit7 MBZ（non-zero is invalid） |
| `count_complete_mask` | bit0 Mode35 all-SUPERSEDED-header walk pass complete; bits1..7 MBZ |
| `binding_complete_mask` | bit0 Mode35 chain walk binding complete; bit5 sticky `s6_required_seen`（RETIRED successor encountered）; bits1..4, 6..7 MBZ |
| `walk_substep` | exact 0..4 from §18.16.4; 5..255 invalid |
| `header_state` | 0 none/cleared（SELECT reset）; **substep 0 success で decoded successor witness_state を代入**; substep 3 完了まで保持（quota yield をまたぐ）; 1 ACTIVE; 2 SUPERSEDED; 3 RETIRED; 4..255 invalid |
| `entry_found` | exact 0 or 1; 2..255 invalid |
| `sha_block_len` | 0..63 while SHA is open; 64..255 invalid |
| `drive_get_quota` / `drive_gets_used` | quota exact 1..256 while driving; used 0..quota; used>quota, quota 0, or quota>256 invalid |

At `begin_profiled_d3s5`, all state/masks/pins are zero, then `focus_mode=35` is installed and phase enters BASELINE。SELECT_HEADER resets per-header walk state（walk_steps, walk_substep, streamed_members, SHA, entry_found, header_state, digest pins, predecessor key）but preserves count/binding completion masks and sticky bit5。Mid-yield preserves every field。Mode35 pass exhaustion sets count bit0 + binding bit0, then phase becomes COMPLETE。Any invalid/MBZ value is terminal corruption before readiness derivation。Finalize samples disposition; cleanup-success publishes; every terminal cleanup zeros entire S5 context after Port cleanup。

#### 18.16.11 Memory ceilings（S4 **960** fixed from main）

| Object | Ceiling |
| --- | ---: |
| scanner / Stage5-alone | **8192** / **8704** unchanged |
| S1 / S2 | **448** / **320** unchanged |
| S3（§18.14 main） | **754 / 768**; outer **9920** |
| S4（§18.15 main） | **949 / 960**; full S1+S2+S3+S4 **10880** |
| **S5** | sizeof **651** / ceiling **656** |
| S1+S2+S5 | 8384+448+320+656 = **9808** |
| **S1+S2+S3+S4+S5 full** | 8384+448+320+768+960+656 = **11536** |

Packed full: `8384+421+306+754+949+651=11465`；align8 **11472** ≤ **11536**。
Packed S1+S2+S5: `8384+421+306+651=9762`；align8 **9768** ≤ **9808**。

dual-bound **forbidden**。Stage5 no D3 bind until S12。

#### 18.16.12 Private API（contract names only）

| API | Rule |
| --- | --- |
| `begin_profiled_d3s5` | mode 35 only; ctx ≤**656**; disjoint; not dual-bound |
| `d3s5_drive` / advance | enforce quota; **substep progress**; mid yield |
| finalize/abort | §18.16.8 exact private carrier, whole-output publication/poison, cleanup, zero order |
| Stage5 until S12 | no begin_d3s5 |

#### 18.16.13 Oracle architecture / constructible positives / anti-false-pass

The implementation change set shall add the append-only authority format **`ninlil-domain-scan-crossrow-v1-d3s5`**。It retains the D3-S1 exact 94-vector prefix and the then-current D3-S2/D3-S3/D3-S4 prefix byte-for-byte; this docs-only freeze does **not** edit the existing JSON。An independent deterministic generator, separate from production scanner control flow, must emit both (a) Port fixture records/scripts and (b) the expected per-drive state transition, exact-get key sequence, masks, disposition, and terminal result。The production bridge must run those generated scripts through the private D3-S5 implementation。

**Minimum constructible positive catalog:**

1. Mode35, single SUPERSEDED header W1（revision=2）→ successor W2 ACTIVE, W2 manifest M=2（entry 0: ordinary semantic member, entry 1: SUPERSEDE_WITNESS for W1）, canonical old digest matches → `LOCAL_COMPLETE`。walk_steps=1, no cycle。
2. Mode35, chain W1→W2→W3（W1/W2 SUPERSEDED, W3 ACTIVE）, `drive_get_quota=1` → exact hop/chunk/substep cursor sequence, no repeated get, walk_steps=2 from W1 origin。Each hop verifies its own successor manifest entry with canonical old digest。
3. Mode35, multiple predecessors W1/W2 both SUPERSEDED with same successor W3 ACTIVE → both origins independently verify W3 manifest contains their respective SUPERSEDE_WITNESS entries（M≥2）。
4. Mode35, successor W2 is SUPERSEDED（chain continues）→ hop advances, W2's successor W3 ACTIVE reached, both manifest entries verified。Digest shift（prev/current/successor）at each hop promotion is exact。
5. Mode35, RETIRED successor: W1 SUPERSEDED → W2 RETIRED。W2 header + manifest entry full-M proved **before** S6_REQUIRED set。Finalize returns disposition 2。W2's own successor suffix is not walked。
6. Mode35, bootstrap snapshot with zero witness headers → vacuous complete（count bit0 + binding bit0 set by empty inventory）。
7. Mode35, M=9/C=2 successor manifest → chunk index sequence `[0,0,0,0,0,0,0,0,1]`; SHA feeds at ordinals 0 and 8 only; within-chunk re-get legal。
8. Finalize output carriers: evaluator-on LOCAL_COMPLETE `(present,disposition)=(1,0)`; S6_REQUIRED `(1,2)`; evaluator-off `(0,0)`。

**Minimum negative/mutation catalog:**

1. SUPERSEDED header with `successor_witness_digest == zero` → **must fail**（missing successor）。
2. Successor exact_get ABSENT → **must fail**（missing successor）。
3. Self-reference: `successor_witness_digest == own witness_digest` → **must fail**（cycle）。
4. Two-header cycle: W1→W2→W1 → **must fail**（origin cycle detection）。
5. Long cycle exceeding `walk_bound` → **must fail**（bounded walk; u64 counter）。
6. Successor manifest missing SUPERSEDE_WITNESS entry for predecessor key after full-M → **must fail**（missing entry; `entry_found==0` at close）。
7. SUPERSEDE_WITNESS entry with wrong `old_value_digest`（canonical ACTIVE 合成不一致）→ **must fail**。
8. SUPERSEDE_WITNESS entry with wrong `new_value_digest`（live SUPERSEDED VALUE_DIGEST 不一致）→ **must fail**。
9. SUPERSEDE_WITNESS entry with wrong `record_role`（not family6/7f）→ **must fail**。
10. Manifest SHA mismatch after full stream → **must fail**。
11. `quota=1` re-gets same chunk without `streamed_members` advance → **must fail**。
12. Full-ID set / visited hash table in context → **must fail**（architecture violation）。
13. Two-snapshot list-then-prove → **must fail**（§18.3 prohibition）。
14. Unbounded walk without `walk_bound` check → **must fail**。
15. Any invalid enum/MBZ bit, incomplete required mask → **must fail**。
16. **RETIRED handoff:** manifest proof 前に S6_REQUIRED set / walk 停止 → **must fail**。RETIRED successor の manifest entry を skip して停止 → **must fail**。
17. **revision ≠ 2:** SUPERSEDED carrier with `record_revision==1` or `record_revision==3` → **must fail**。
18. **Canonical ACTIVE digest 不一致:** synthetic old digest computation で successor field を zero にしない / revision を 1 にしない / CRC を再計算しない → **must fail**。
19. **Target entry duplicate:** 同一 predecessor key の SUPERSEDE_WITNESS entry が 2 件 → **must fail**（`entry_found` duplicate reject）。
20. **Wrong final entry-count:** 末尾 chunk の entry_count が `M-8*(C-1)` と不一致 → **must fail**。
21. **Tail-into-cycle:** chain の末尾 SUPERSEDED が origin を指す（3+ hop cycle）→ **must fail**。
22. **Successor state invalid:** successor header state が ACTIVE/SUPERSEDED/RETIRED 以外 → **must fail**（D2 precedence; recognizable-future 以外）。
23. **SHA duplicate-feed:** `i%8 != 0` で chunk body を SHA に再投入 → **must fail**。
24. **Lex order violation:** manifest entry key が `prev_member_key` 以下（decreasing or duplicate across chunks）→ **must fail**（ORDER_CORRUPT）。
25. **Next-hop pin missing:** successor SUPERSEDED の substep 0 で `next_old_digest` / `next_new_digest` を pin せず hop promotion → **must fail**（positive #2/#4 構成不能）。
26. **SHA domain separator skip:** manifest SHA 初期化時に `ASCII("NINLIL-DOMAIN-MANIFEST-V1")` を投入せず chunk body から開始 → **must fail**。
27. Whole-result poison tests: abort（cleanup success and failure）、finalize cleanup failure、NULL/alias/prevalidation/invalid-state/incomplete-shape all leave every output byte unchanged。Alias mutations cover overlap with session, workspace, ops, handle slot, and bound S5 context。Invalid carrier combinations `(present>1)`, `(present=0, disposition!=0)`, `(present=1, disposition==1)`, `(present=1, disposition>2)` are never published。

Each positive fixture must be materialized, reproducible from a pinned seed/version, and self-check its expected get keys against keys independently reconstructed from fixture raw fields。CI must reject stale generated output, changed prefix vectors, duplicate vector IDs, nondeterministic regeneration, or a production result/state trace differing from the generated expectation。

#### 18.16.14 Mutation / D4 boundary

Snapshot finding **S5**; retire/cleanup **S6**; commits **D4**。S5 は Storage mutation 0（D2/S4 と同）。

#### 18.16.15 Explicit exclusions

| Exclusion | |
| --- | --- |
| Full-ID set / visited hash table / unbounded walk | forbidden |
| Two-snapshot list-then-prove（§18.3） | forbidden |
| quota=1 infinite same-get loop | forbidden |
| KEY_DIGEST reverse | forbidden（§18.5） |
| ACTIVE successor-zero check（D1/D2-S3 header-local） | not S5 |
| S6 retire/cleanup physical erase truth | not this freeze |
| D4 mutation / commits | not this freeze |
| Incoming predecessor reference walk（S6 duty） | not this freeze |
| RETIRED retirement eligibility proof | not this freeze |
| RETIRED node's own successor suffix walk | not this freeze（S6 handoff） |
| public ABI/wire/D1 change | not this freeze |
| S4 deferred disposition re-issue/overwrite | forbidden |
| Non-existent wire field comparison（entry successor field） | forbidden |

#### 18.16.16 Completion boundary / non-claims

| Claim | |
| --- | --- |
| D3-S5a Normative freeze §18.16（DSW2 bounded walk; cycle/missing/self detection; SUPERSEDE_WITNESS manifest entry full-M proof + lex order; canonical NLR1 old digest; hop_witness_digest 別 pin; RETIRED handoff; 651/656; full outer 11536） | **yes** |
| S4a §18.15 main-equivalent 949/960/10880 | **preserved** |
| S5 / D3 / Stage5 / Runtime / ESP implementation | **no** |
| Crossrow d3s5 JSON | **no** |

S5a を implementation complete へ書き換えない。S0/S1a/S2a/S3a/S4a historical は **preserve**。

#### 18.16.17 Worked example: W1→W2→W3（positive #2/#4 構成可能性確認）

Chain: W1(SUPERSEDED, rev=2, successor=W2) → W2(SUPERSEDED, rev=2, successor=W3) → W3(ACTIVE, successor=zero)。W2 manifest M=2（entry 0: semantic member, entry 1: SUPERSEDE_WITNESS for W1）。W3 manifest M=2（entry 0: semantic member, entry 1: SUPERSEDE_WITNESS for W2）。

**SELECT_HEADER（origin W1）:**
```
witness_digest        := W1
origin_witness_digest := W1
successor_witness_digest := W2        (from W1 body)
predecessor_complete_key := key(W1)
expected_entry_old_digest := canonical_old(W1)   (rev=1,state=ACTIVE,succ=zero,CRC,SHA)
expected_entry_new_digest := VALUE_DIGEST(W1 live SUPERSEDED value)
last_carrier_key := key(W1)
```

**Hop 1 substep 0（get W2）:**
```
peer_key := build_header_key(successor_witness_digest=W2)
exact_get(peer_key) → W2 live
# cycle checks: W2 != W1(origin), W2 != prev_hop(none) → OK
hop_witness_digest := W2              ← W2 自身の identity（chunk key 用）
header_state := 2                     ← W2 decoded witness_state (SUPERSEDED); substep 3 まで保持
successor_witness_digest := W3        ← W2 body の successor field（次 hop 用）
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W2)
header_state==2 (SUPERSEDED) →
  next_old_digest := canonical_old(W2)
  next_new_digest := VALUE_DIGEST(W2)
SHA init: feed ASCII("NINLIL-DOMAIN-MANIFEST-V1") (25 bytes)
# W2 value dies hereafter; header_state=2 retained
```

**Hop 1 substep 1-2（stream W2 manifest, M=2, C=1）:**
```
i=0: chunk_key(hop_witness_digest=W2, floor(0/8)=0) → exact_get → chunk live
     SHA feed chunk body (i%8==0)
     entry[0]: action=2(REPLACE), key=semantic_member_key → not target; lex OK (prev=∅)
     prev_member_key := semantic_member_key; streamed_members=1
i=1: same chunk re-get (i%8=1, no SHA feed)
     entry[1]: action=4(SUPERSEDE_WITNESS), key=key(W1) == predecessor_complete_key → MATCH
       entry_found==0 → verify:
         old_value_digest == expected_entry_old_digest (W1 canonical old) ✓
         new_value_digest == expected_entry_new_digest (W1 live new) ✓
         record_role == 0x067f ✓; prior_head == zero ✓
       entry_found := 1
     lex: key(W1) > semantic_member_key ✓; prev_member_key := key(W1); streamed_members=2
```

**Hop 1 substep 3（full-M close + promotion）:**
```
streamed_members==2==M ✓; entry_found==1 ✓; visited chunks==1==C ✓
final SHA == expected_manifest_digest ✓
# branch on pinned header_state==2 (SUPERSEDED) → promote:
prev_hop_witness_digest := witness_digest = W1   # OLD current becomes prev
witness_digest := hop_witness_digest = W2        # new current
predecessor_complete_key := build_header_key(W2) = key(W2)
expected_entry_old_digest := next_old_digest (W2 canonical old)
expected_entry_new_digest := next_new_digest (W2 live new)
walk_steps := 1
streamed_members := 0; entry_found := 0; prev_member_key_len := 0
SHA re-init: feed domain separator (25 bytes)
# successor_witness_digest = W3 (unchanged from substep 0 pin)
→ substep 0 (next hop)
```

**Hop 2 substep 0（get W3）:**
```
peer_key := build_header_key(successor_witness_digest=W3)
exact_get(peer_key) → W3 live
# cycle checks: W3 != W1(origin) ✓, W3 != W2(prev_hop) ✓ → OK
hop_witness_digest := W3              ← W3 自身の identity
header_state := 1                     ← W3 decoded witness_state (ACTIVE); substep 3 まで保持
successor_witness_digest := zero      ← W3 body successor (ACTIVE → zero)
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W3)
header_state==1 (ACTIVE) →
  next_old_digest / next_new_digest: NOT computed (chain stops)
SHA init: feed domain separator
# W3 value dies; header_state=1 retained
```

**Hop 2 substep 1-2（stream W3 manifest, verify W2's entry）:**
```
i=0: chunk_key(hop_witness_digest=W3, 0) → exact_get → chunk live
     SHA feed; entry[0]: semantic → not target; lex OK; streamed_members=1
i=1: re-get; entry[1]: SUPERSEDE_WITNESS, key=key(W2)==predecessor_complete_key → MATCH
       old == W2 canonical old ✓; new == W2 live new ✓; role/head ✓
       entry_found := 1; lex OK; streamed_members=2
```

**Hop 2 substep 3（full-M close + WALK_CLOSE）:**
```
full-M close ✓ (entry_found=1, SHA match)
# branch on pinned header_state==1 (ACTIVE) → WALK_CLOSE (no promotion)
walk_steps := 2
→ phase WALK_CLOSE → W1 origin header complete → next SELECT
```

**SELECT_HEADER（W2 as independent carrier）:**
W2 も SUPERSEDED なので、iterator は `last_carrier_key=key(W1)` の strictly after から resume し、W2 を次の carrier として select する。
```
witness_digest        := W2
origin_witness_digest := W2            # new origin
successor_witness_digest := W3         (from W2 body)
predecessor_complete_key := key(W2)
expected_entry_old_digest := canonical_old(W2)
expected_entry_new_digest := VALUE_DIGEST(W2)
last_carrier_key := key(W2)
walk_steps := 0 (reset per origin)
```

**W2 origin Hop 1 substep 0（get W3）:**
```
peer_key := build_header_key(successor_witness_digest=W3)
exact_get(peer_key) → W3 live
# cycle checks: W3 != W2(origin) ✓, W3 != prev_hop(none) ✓
hop_witness_digest := W3
header_state := 1                     ← W3 ACTIVE; substep 3 まで保持
successor_witness_digest := zero (W3 ACTIVE)
member_count := 2; chunk_count := 1; expected_manifest_digest := man(W3)
header_state==1 → next_old/new NOT computed
SHA init: feed domain separator
```

**W2 origin Hop 1 substep 1-2（stream W3 manifest, verify W2's entry）:**
```
i=0: chunk_key(hop_witness_digest=W3, 0) → exact_get → chunk live
     SHA feed; entry[0]: semantic → not target; lex OK; streamed_members=1
i=1: re-get; entry[1]: SUPERSEDE_WITNESS, key=key(W2)==predecessor_complete_key → MATCH
       old == W2 canonical old ✓; new == W2 live new ✓; role/head ✓
       entry_found := 1; lex OK; streamed_members=2
```

**W2 origin Hop 1 substep 3（WALK_CLOSE）:**
```
full-M close ✓; branch on pinned header_state==1 (ACTIVE) → WALK_CLOSE
walk_steps := 1
→ W2 origin header complete → next SELECT
→ iterator: no more SUPERSEDED carriers after key(W2)
→ COMPLETE; count_complete_mask.bit0=1; binding_complete_mask.bit0=1; bit5=0
→ finalize: disposition (1, 0) = LOCAL_COMPLETE
```

**Complete session get sequence（M=2, C=1）:**
- W1 origin: `H(W2), C(W2,0)×2, H(W3), C(W3,0)×2`（6 gets）
- W2 origin: `H(W3), C(W3,0)×2`（3 gets）
- Total: 9 exact_gets

**構成可能性確認:** positive #1（single hop W1→W2 ACTIVE, M=2）は W1 origin だけで W2 ACTIVE なら substep 3 で WALK_CLOSE。positive #2/#4（W1→W2→W3 multi-hop）は W1 origin の Hop 1→Hop 2 digest shift + W2 independent carrier の両方で構成可能。positive #5（RETIRED）は W1→W2 RETIRED で `hop_witness_digest=W2` を使い W2 manifest を full-M 検証後 bit5 set → WALK_CLOSE → disposition (1,2)。全 positive が構成可能であることを確認した。

---

## TBD 確定表（r1 レビュー提示案の docs 正本照合結果）

| TBD | レビュー確定案 | 正本照合 | 採否 |
| ---: | --- | --- | --- |
| 1 RETIRED successor | manifest proof 後に S6_REQUIRED set + 停止; RETIRED suffix は S6 移管 | §10.2: RETIRED は incoming reference ある間 complete 保持; §18.2 S6 行: incoming successor 参照 0 / cleanup eligibility = S6。manifest proof 前の停止は S5 の successor existence 証明を不完全にする | **採用** |
| 2 ACTIVE digest | revision==2 必須; canonical NLR1 変換（rev=1, state=ACTIVE, successor=zero, CRC 再計算, SHA-256） | §4: record_revision は 1 始まり replacement +1; §10.1: ACTIVE→SUPERSEDED は exactly 1 replacement; §12 6.2: NLR1 envelope fully specified（magic/type/ver/len/payload/CRC32C）; VALUE_DIGEST = SHA-256(complete NLR1 bytes)。3 field 置換で payload_length 不変、CRC/SHA 再計算は deterministic | **採用** |
| 3 RE_SUPERSEDE | 存在しない successor field 比較を削除; revision==2 + canonical old + live new + entry exact 1 + raw/key bijection の組合せ | §10.1 entry encoding: record_role/action/key/old_present/new_present/prior_head/old_value_digest/new_value_digest のみ。successor field は存在しない。§10.1「別successor」は successor_witness_digest と actual successor header の不一致で検出 | **採用** |
| 4 flags.bit7 | MBZ 確定 | S5 は S5_REQUIRED を生成しない（S5 自身が successor proof）。S4 の bit7=s5_required_seen とは役割が異なる | **採用** |
| 5 walk bound u64 | baseline full scan で独立 checked-u64 count; walk_bound/walk_steps は u64 BE | §18.5 category E:「visited step ≤ witness row count」に width 制限なし。witness header 数に 65535 上限なし（§10.1 member_count 256 × chunk 32 は manifest 内の制限であり header 総数の制限ではない） | **採用** |
| 6 alignment | 全 field uint8_t scalar/array; multi-byte は BE byte array; alignof==1 + _Static_assert | S4 §18.15.12:「align 1」明示。S1/S2/S3 も packed byte array 前提 | **採用** |
| 7 RETIRED carrier | Mode35 origin は SUPERSEDED だけ; RETIRED は TBD1 到達時 handoff のみ; 独立起点の retire/incoming walk は S6 | §18.2 S6 行:「SUPERSEDED→RETIRED、incoming successor 参照 0、oldest-first chunk partial cleanup eligibility」= S6。S5 の carrier は SUPERSEDED に限定 | **採用** |

---

## 移植時 checklist（docs/17 本体へ採択する際）

- [ ] §18.2 D3-S5 行に `§18.16 freeze` 参照を追加
- [ ] **§18.2 D3-S6 行に outgoing successor suffix authority を追加**（r2 P1-2: S5 が RETIRED node の successor suffix・retirement/incoming/partial truth を S6 へ移管するため、S6 exact scope に「RETIRED node の outgoing successor suffix walk / chain authority」を明示追加。将来 S6a freeze にも反映）
- [ ] §18.3 hybrid に S5a specialization 段落を追加
- [ ] §18.4 D3 fixed context size に S5a addition を追加（651/656; full outer 11536）
- [ ] §18.5 category E に S5a freeze 参照を追加
- [ ] §18.5 `k` 表に `k₅=1（mode 35）` を追加
- [ ] §18.6 DSW2 行に S5 freeze 参照を追加
- [ ] §18.10 Fixed D3 descriptor 行に S5a freeze を追加
- [ ] §18.11 completion boundary に S5a を追加
- [ ] §15 / §16 / §17 の D3 status 記述に S5a docs freeze を反映
