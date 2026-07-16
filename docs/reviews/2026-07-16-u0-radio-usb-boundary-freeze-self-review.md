# U0 radio-USB boundary freeze — self-review

状態: **docs-only self-review（非規範）**
対象: `docs/23-usb-radio-boundary.md`、`docs/adr/0003-radio-usb-dependency-direction.md`、`tools/radio_usb_boundary_docs_gate.py`、関連 index/glossary/versioning 整合
日付: 2026-07-16（root QA 追加修正反映）
Branch: `codex/radio-usb-boundary-spec`
範囲: **docs / gate のみ**（USB / SX1262 production code **未実装**）

## Scope honesty

| 項目 | 状態 |
| --- | --- |
| U0 boundary freeze 文書 | 本 PR 作業対象（uncommitted docs/gate） |
| USB production code | **未実装** — 完成主張しない |
| SX1262 production code | **未実装** — 完成主張しない |
| U4 vector 実 fixture / codec bridge | **未実施**（U0 は vector ID+意味のみ; U4 PR で Required） |
| U1/U2/U7 Required HIL | **未実施** |
| U7 liveness 数値の測定確定 | **未実施**（§8.11 は profile default のみ） |
| `esp_tinyusb` exact managed version / lock | **未 pin（U2）** — U0 は path 選定のみ |
| Cell continuity-loss notice / `UINT32_MAX` sequence の実装 | **未実装** — docs+gate+vector ID のみ |
| セキュリティ監査 / AEAD / identity bind | **本レビュー対象外**（Fable 非セキュリティ視点; 逸れない） |

## Sources of findings

1. **Fable 非セキュリティ / OSS 人間視点レビュー**（control session 回復、型 matrix、counter/liveness の exact 化、DX/語彙、読み順、self-review）
2. **独立レビュー / 先行 U0 作業**（cookie header authority、NCG1 sequence U4 policy、stream_id=0、Permit/R9、false-green gate、CSPRNG fail-closed 等）
3. **独立最終レビュー NO-GO（A–E）** — 下記 A–E を **旧 NO-GO として正直に記録**し、docs+gate 上の closure のみ主張（実装/HIL は未）
4. **Root QA 追加修正（本改訂）** — §5.2 Link down 混同、Cell continuity-loss 通知順序、`RESET_PARSER`/`RESET_LINK` 表の曖昧さ、`UINT32_MAX` 予約 terminal、role matrix exact parse、ADR esp_tinyusb path vs U2 lock
5. **独立再レビュー NO-GO（P1-A/P1-B）** — pending continuity notice の sender lifecycle と stale RESET の sequence 消費矛盾を検出し、docs+gate を再修正

## Independent final NO-GO（旧状態 → 本改訂）

| ID | 旧 NO-GO（未解消だった欠陥） | 採否 | 文書上の修正 | 実装/HIL |
| --- | --- | --- | --- | --- |
| **A** | ACK loss: HELLO seq0 / ACK seq0 喪失 → re-HELLO seq1 / re-ACK seq1 を Controller が exact0 baseline で永久拒否 | **採用し解消（docs）** | §5.5.3 **SBR-ACK** + §5.6.1 reverse ACK 経路 + vector `U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE` | **未検証** |
| **B** | Controller process restart 後、Cell TX high の HELLO_ACK を新 Controller が拒否 | **採用し解消（docs）** | 自側 restart は TX+RX 双方 cold; Cell half-open/`BOOTSTRAP_EPOCH_RESTART`; Controller **SBR-ACK** high ACK + `U4-G-RESTART-ACK-HIGH-BASELINE` | **未検証** |
| **C** | Cell が gap/overflow/fatal desync で local TX/RX 双方 cold すると、Controller high HELLO を Cell が baseline 拒否 | **採用し解消（docs）** | gap/overflow/`RESET_PARSER` は **RX-only cold + TX 継続**; Cell **SBR-HELLO**; `U4-G-CELL-RXCOLD-HIGH-HELLO` | **未検証** |
| **D** | RESET 送信 role / request_id authority 矛盾 | **採用し解消（docs）** | role matrix: RESET 双方可; request_id は local allocator nonzero・**inflight 非登録**; §8.3 code 別 TX/RX 動作 | **未検証** |
| **E** | gate false-green ≥8（BOOTSTRAP accept→reject、ACKLOSS next_tx→cold0、RESET_SESSION→cold、ping slack 1000→60000、dispatch miss fence 削除、U1 HIL AND→OR、overflow recovery 無効、reverse ACK 削除） | **採用し解消（gate）** | row/section scoped parser + 本改訂 mutation が実 checker を落とす | gate self-test のみ |

## Root QA 追加（本改訂で docs+gate 上 closed）

| ID | 指摘 | 採否 | 反映先 | 実装/HIL |
| --- | --- | --- | --- | --- |
| **QA1** | §5.2 規則1 が RX overflow/RESET を **Link down** と呼び、re-Link 無し HELLO 回復と矛盾 | **採用し解消（docs）** | §5.2: **物理 Link down (a)** vs **session-breaking (b)** 分離; re-Link 不要を明示 | **未実装** |
| **QA2** | Cell continuity-loss の `RESET_SESSION` 通知順序が exact でない（fence 後 header / WOULD_BLOCK） | **採用し解消（docs）** | §5.6.1 pre-fence snapshot → atomic fence + notice 最大 1; §4.5/§7.4/§8.3 整合; `U4-G-CELL-CONTINUITY-RESET-SESSION` | **未実装** |
| **QA3** | `RESET_PARSER` TX/RX と `RESET_LINK` session/sequence 表が曖昧 | **採用し解消（docs）** | §5.5.2 authority 行 + §8.3: 各端 **local RX-only cold + local TX 継続**; `RESET_LINK` session **即 INVALID**・sequence は **観測 reopen 双方 cold** | **未実装** |
| **QA4** | `sequence == UINT32_MAX` と last+1 wrap が未固定 | **採用し解消（docs+gate）** | U4 予約 terminal; SBR/BOOTSTRAP より前 reject; `ncg1_reject_seq_reserved`; `U4-N-SEQ-U32-MAX` | **未実装** |
| **QA5** | role matrix が soft 検査のみ（Cell RESET 禁止等 false-green） | **採用し解消（gate）** | 各行セル exact parse; HELLO/PING C-only, ACK/PONG Cell-only, RESET/CTRL_ERROR both; RESET Cell 禁止 mutation | gate self-test のみ |
| **QA6** | ADR “pinned esp_tinyusb path” が exact version pin と誤読されうる | **採用し解消（docs）** | path 選定のみ; exact version/lock は **U2**（§3.1 + ADR §5） | U2 まで OPEN |
| **QA7 / P1-A** | `WOULD_BLOCK` で残った旧 continuity notice が valid HELLO 後に TX accept され、Cell 自身が回復中/新 session を再 fence しうる | **採用し解消（docs+gate）** | sender fence は検出時 exact 1 回; 未 accept notice は HELLO 遷移直前に atomic cancel + `continuity_reset_notice_cancelled`; accept 済みは HELLO_ACK より FIFO; cancel/accept の sequence 消費点を固定 | **未実装** |
| **QA8 / P1-B** | 連続 stale RESET を semantic drop 時に sequence 不変とすると、次の正規 frame が false gap になり新 session を間接 fence する | **採用し解消（docs+gate）** | NCG1 sequence accept を先に行い、連続 stale は `last_rx_seq` 前進を保持; control session のみ不変。dup/regress/gap/reserved は通常規則、stale に SBR/baseline 特権なし | **未実装** |

**Closure 規則:** 「closed」は **docs+vector ID+gate/self-test 上**に限る。U4 fixture bridge / 実コード / Required HIL / 測定 / `esp_tinyusb` lock は **OPEN**。未実装を closed と過大主張しない。

## Disposition table（先行 + 維持）

| ID | 出典 | 指摘 | 採否 | 反映先 | 文書上 closure |
| --- | --- | --- | --- | --- | --- |
| F1 | Fable | Half-open: Controller restart / HELLO_ACK 喪失で物理 link down 無しでも回復。valid HELLO は gen=0/cookie=0。ACTIVE 中 fence→HELLO_RECEIVED | **採用** | §5.6 / §5.6.1 | **closed（docs）**; 実装未 |
| F1b | 独立 | 同一 process HELLO timeout は cold 禁止・`next_tx_seq`。restart は `BOOTSTRAP_EPOCH_RESTART`。**SBR-ACK/SBR-HELLO と RX-only cold を合成** | **採用** | §5.5.2–5.5.3 / §5.6.1 / §8.1 | **closed（docs）**; 実装未 |
| F2 | Fable | NCG1↔NCL1 closed matrix + validation 順 | **採用** | §7.3 / §8.1 | **closed（docs）** |
| F3 | Fable | type binding negatives | **採用** | §7.3.2 / vectors | **closed（docs）** |
| F4 | Fable | 数値 namespace 説明 | **採用** | §7.3 | **closed** |
| F5 | Fable | counter catalog | **採用** | §8.10（+ baseline resync + `ncg1_reject_seq_reserved`） | **closed（docs）** |
| F6/F6b/F6c | Fable/独立 | liveness monotonic + fair-delivery + PING MUST dispatch + inflight=1 | **採用** | §8.11 | **closed（docs）**; 測定 OPEN |
| F7–F10 | Fable | self-review / 読み順 / Join 語彙 / DX | **採用** | 各所 | **closed（docs）** |
| F11/F12 | Fable/独立 | gate 構造検査 + mutation | **採用＋本改訂追加** | `radio_usb_boundary_docs_gate.py` | **closed（gate）** |
| I1–I5 | 独立/先行 | cookie header / sequence / stream0 / Permit / CSPRNG | **維持** | 各所 | **closed（docs）** |
| I6/I7 | 範囲 | セキュリティ完成 / 実機 HIL を U0 PASS 扱い | **不採用** | Acceptance 未チェック | n/a |
| QA1–QA8 | Root QA / 独立再レビュー | 上記 Root QA 表 | **採用** | docs+gate | **closed（docs/gate）**; 実装 OPEN |

## Design choices fixed this pass（要約）

1. **方向別 TX/RX sequence epoch:** RX gap/overflow/`RESET_PARSER`/fatal desync/`UINT32_MAX` → **RX-only cold + session INVALID**; local TX 継続。物理 link down→up / 自 process restart → **双方 cold**。wrap/`next_tx_seq==UINT32_MAX` → 当該 TX 停止/fence（予約 terminal を wire に載せない）。
2. **exact0 baseline 維持 + 限定 SBR 2 種:** Cell baseline 未成立 + valid HELLO（SBR-HELLO）; Controller HELLO_SENT + matching sole HELLO_ACK（SBR-ACK; error ACK も matching 可）。**`UINT32_MAX` は SBR/BOOTSTRAP より前 reject**。非 HELLO/non-matching は baseline にしない。
3. **RX continuity 有限回復 + Cell notice exact:** Controller 検出 → 即 `next_tx_seq` HELLO; Cell 検出 → **pre-fence snapshot** + atomic fence + 高優先 `RESET_SESSION` notice 最大 1（継続 seq / snapshot header）。`WOULD_BLOCK`/喪失でも fence 非 rollback。`RESET_LINK` は補助・必須脱出口ではない。
4. **RESET authority:** 双方送信; nonzero request_id を local allocator から・**inflight 非登録**; `RESET_PARSER` は **各端 local RX-only**; `RESET_LINK` は session 即 INVALID + reopen で双方 sequence cold。
5. **§5.2 規則1:** 物理 Link down と session-breaking を分離。overflow/RESET を Link down と呼ばない。
6. **必須 vectors** A–C + continuity-loss + `U4-N-SEQ-U32-MAX` と negative nonmatch/non-HELLO を §5.6.2 / §8.9 に追加。
7. **P2:** ESP-IDF **v5.5.3** のみ U0 pin; `esp_tinyusb` は **path 選定のみ**、exact lock は **U2**; U1/U7 Required HIL は **Linux および macOS**; U7 soak ≥30 min continuous 宣言。
8. **Liveness:** `ping_dispatch_slack` は row-scoped **1000 ms**。期限内 TX accept 不能時は session fence + `next_tx_seq` re-HELLO とし、ACTIVE のまま放置しない。
9. **遅着とCell restart:** continuity-loss RESET の pre-fence snapshot は送信側だけの例外。旧noticeは新sessionをfenceしない。Cell restart時のACK seq0 regress→RX-only cold→immediate re-HELLO→SBR-ACK回復を必須vector化。
10. **Pending notice lifecycle:** fence は continuity-loss 検出時の1回だけ。未accept noticeはvalid HELLO前にatomic cancel、accept済みはHELLO_ACKよりFIFO先、cancelはsequence非消費・acceptは通常消費。
11. **Stale RESET sequence order:** sequence validation/acceptを先行。連続staleは`last_rx_seq`前進を保持したままsemantic dropし、control state/sessionを変えない。専用mutationを含む**63 mutation**でfalse-greenを検査。

## Residual risks / unfinished（未実装を隠さない）

1. SBR / half-open / RX-only cold / continuity-loss / `UINT32_MAX` 予約は **文書+gate 上 closed**。**実装・vector bridge は U4 まで未検証**。
2. §8.11 数値は default。U7 未実施のため **測定済み SLO ではない**。有限時間回復は fair-delivery assumption 下の論理のみ。
3. Counter 名は private 安定集合。public diagnostics schema は U7。
4. Owner Task Join の C 記号 rename は **意図的未実施**（docs-only）。
5. docs/03 本線・relay・multi-parent は **未 freeze**。
6. `esp_tinyusb` managed component の **exact version/lock は U2 未着手**。
7. default build-type の installed-consumer 失敗は **本 docs slice とは別の既知 main 問題**。
8. public ABI / production USB・SX1262 source は **本改訂で変更しない**（docs/gate のみ）。

## Greps / gates（実施時）

```bash
rg -n "SBR-HELLO|SBR-ACK|BOOTSTRAP_EPOCH_RESTART|RX-only cold|next_tx_seq|UINT32_MAX|pre-fence snapshot|ncg1_reject_seq_reserved|規則1\\(b\\)|path 選定" docs/23-usb-radio-boundary.md
python3 -m py_compile tools/radio_usb_boundary_docs_gate.py
python3 tools/radio_usb_boundary_docs_gate.py check
python3 tools/radio_usb_boundary_docs_gate.py self-test
git diff --check
```

Self-review author: main-spec implementer applying independent final NO-GO closure (A–E) + Root QA / independent re-review (QA1–QA8) + prior Fable dispositions. Not Normative. Not a security audit. **Does not claim production code or HIL PASS.**
