# Ninlil Runtime 完成 master plan（orchestrator: Fable）

状態: **rev2**（Sol high NO-GO P0-4 / P1-3..P1-10 反映; 再レビュー待ち）
作成: 2026-07-21。台帳は docs/work/ 配下で継続更新。

## 0. 完成条件(root指示の再掲・凍結)

public Runtime、POSIX/ESP-IDF ports、PC間E2E、USB Controller/Cell Agent、SX1262 radio software path、Join/Attachment、relay、multi-parent、fragmentation、priority/deadline/retry、複数Capability Service、汎用ApplicationData、security、Japan compliance enforcement、CI、Apache-2.0 packaging、examples、利用者/開発者文書、release candidate までを**コード + 非実機検証で接続済み**にし、残作業が「物理実機の flash / USB / RF / power-cut / Display node / Leak node E2E」だけであることを証拠付きで限定する。stub / TODO / 未接続candidate / compile-only を完成扱いしない。application-specific語彙をportable Coreへ入れない。

**CI前提(Sol high P1-10)**: Linux/macOS + ESP-IDF target build + ASan/UBSan の最小matrixは**各トランチのmerge前提条件**であり、後段トランチではなく常時適用する。CI/レビュー赤のmerge禁止。commit/PRは日本語。

## 1. 現状監査の要約(証拠: README / docs/09 / git / 実測)

- **済(実装+検証)**: public ABI宣言、L1 lifecycle、Runtime Store v1 codec/L2a2/L2b1、Stage5 empty-metadata private、D1全body codec(B1..B3o)、D2-S3..S6、D3-S1、D3-S2、R1..R5候補、R6 N6、R7 T0/T1/T1b、U1..U4候補、POSIX SQLite storage候補、ESP dual-slot storage候補、M3系候補群。
- **進行中**: D3-S3(oracle R27-Sol Proposed 280 green / production bridge RED 9 = A1トランチ)。
- **未**: D3-S4..S12、Stage5 D3 bind、D4 convergence、public Runtime body、provider統合、M4 Join/Attachment、T1c以降のsecure wire残、U5..U7、relay、multi-parent、application capability群、compliance本経路、PC間E2E、packaging/examples/docs/RC。

## 2. トランチ列(依存順; 各トランチ = 仕様固定→Sol high計画レビュー→Qwen実装→Grok/Sol xhighレビュー→QA→PR→CI→merge→README/push)

### Phase A — Domain Store完成
1. **A1: D3-S3回収**(進行中; 別紙 rev2)。
2. **A2: D3-S4 witness**(§18.15実装; oracle先行→bridge)。
3. **A3: D3-S5..S12**(EVIDENCE live cardinality / witness chain / capacity / health / recovery順; sliceごとにoracle→production)。
4. **A4: Stage5 D3 bind + D4 commit-unknown convergence**。

### Phase B — public Runtime縦切りとports本体
5. **B1: public Runtime body**: 14 API正本semantic、`runtime_step`、service_register/submit/cancel/event_resume|discard/delivery durable path。INTERFACE→実体化。
6. **B2: 全provider統合(Sol high P1-4)**: platform.hの**全provider**(allocator / execution / clock / entropy / storage / bearer / TxGate / origin authorization)について、POSIX/ESP factory、ownership、shutdown、restart、fault conformance、Runtime body接続を完成条件とする。storage(SQLite/dual-slot)+Stage5 recovery writer+restart E2E含む。
7. **B3: 論理capability層(Sol high P1-5)**: priority/deadline/retryの本経路、**logical payload/fragment capabilityとreservationまで**(実wire fragmentation/reassembly/custodyはC5へ分離)。simulated bearerで検証。
8. **B4: PC間 direct 1-hop E2E(Sol high P1-6; roadmap M1b)**: 2-process loopback bearer(simulated/USB loopback)でsubmit→deliver→evidence→restartのE2E。relay/multi-parentより**前**。
9. **B5: application capability群(Sol high P1-3; roadmap M1b/M2)**: 複数ServiceDescriptor登録・分配(=「複数Capability Service」の定義を固定)、multi-target/`ALL_TARGETS`、LatestState、MeasurementBatch、BoundedTransfer、ConfigRevision、target resolver、counter-offer、subscription。ApplicationDataは独立public typeではなく Transaction+payload+descriptor snapshot の概念record(docs/02)として実装。
    **B5受入条件(再レビューP1反映)**: M1b——loss込み2-process E2E、target別Outcomeと決定的aggregate、partial-result query、失敗targetの再実行を新transactionとして追跡。M2——family別backpressure/retention/supersede/aggregation、BoundedTransferのpartial-apply=0保証、counter-offerの生成・保存・acceptance race解決、public ABI非破壊(破壊時はmigration手順の実装+検証)。

### Phase C — secure wire / Join / USB / radio(Sol high P0-4順序)
10. **C1: R7 stateless primitives残**(M4非依存のstateless primitive閉包のみ。**T1c実装は含めない**——T1cはM4 mint tokenを消費するstateful ownerのためC3へ)。
11. **C2: M4 Identity / Membership / Attachment(Join)**: roadmap M4のhandshake、install token mint、site membership。T1cのtoken入力を供給する側。
12. **C3: T1c実装 + authenticated context install + M5 + R7 state系**: T1c token consume→context install、resume/M5、counter/nonce/AEAD/replay/durable admission、FRAG/LINK/CELL/HA state、W1/L1。
13. **C4: USB series完成(Sol high P1-7)**: U5/U6/U7に加え、U1–U4候補の**完成昇格**(composition、payload ownership、HELLO recovery、fuzz、target final-link)。HILのみ明示的残件。
14. **C5: application radio path / SX1262 software path完結(Sol high P1-8)**: R1–R9 closure(IRQ/FIFO/RX path、immutable plan→permit consume→SPI TXのsole-edge graph、RX authentication/replay admission、host SPI/radio simulation)。R8非採用でもMAC ownerを明示。**実wire fragmentation/reassembly/custody/restart**(B3の論理層をwireへ接続)。
15. **C6: Japan compliance enforcement(Sol high P1-9)**: 対象profileの具体channel/power/LBT/rest値、RegulatoryProfile signer/配布/revocation、credential storage。enforcement対象はDATAに限らずbeacon/Join/ACK/retry/relay/diagnostics全frame。後続トランチで新frame追加時はsole-edge gate再適用を依存として明記。
16. **C7: relay**(roadmap M8)。**C8: multi-parent**(roadmap M9)。別トランチ。各完了時にJoin/Attachment E2E→relay E2E→multi-parent E2Eを段階検証(Sol high P1-6)。

### Phase D — product化
17. **D1: security audit**(fail-closed網羅、threat model、secrets扱い、compliance再検証)。
18. **D2: CI強化**(mutation拡充、ABI/wire/storage互換gate常設、matrix拡張; 最小matrixは§0どおり全トランチ前提)。
19. **D3: packaging(Sol high P1-10)**: Apache-2.0、NOTICE/LICENSE、third-party license、SBOM、release signing、compatibility/migration方針、SECURITY/CONTRIBUTING整備、外部consumer conformance(install/export/subproject)。
20. **D4: examples + 利用者/開発者docs**(Controller/Cell/Display/Leak相当のhost simulation examples含む)。
21. **D5: RC**: 独立最終監査(唯一のFable内蔵サブエージェント使用箇所)→残作業を物理実機系のみに限定する証拠文書→release candidate tag。

## 3. 役割分担(固定)

- **Fable**: 監査、計画、分解、契約抽出、統合QA、進捗台帳、失敗時再委任、README/push、merge判断。
- **Codex GPT-5.6 Sol high**: トランチ計画レビュー(P0/P1解消まで実装開始禁止)。
- **OpenCode Qwen(alibaba-token-plan/qwen3.8-max-preview)**: 主実装。専用worktree/限定編集範囲。**【2026-07-21 23:5x root指示で自動フォールバック停止】実装はupgraded Qwen固定(stall時はQwen再試行→不能ならroot報告)。旧循環(Qwen→Cursor→Grok)は再指示まで無効**（規則詳細: `2026-07-21-worker-fallback-policy.md`。品質不足は切替理由にしない。実装者が誰でもSolレビュー必須。Grok実装期間はGrok自己レビューを独立と数えない）。
- **Grok Build grok-4.5**: 全diffコードレビュー。
- **Codex GPT-5.6 Sol xhigh**: 重大境界(oracle/production、security、wire/ABI/storage format、compliance)レビュー。

## 4. 進捗台帳運用

- 各トランチ: `docs/work/<date>-<tranche>.md` に計画→レビュー→受入証拠→残課題。
- 意味ある区切りごとにREADME更新 + push。
- 禁止事項の常時遵守: dirty D3-S3資産破棄禁止 / `ninlil-r7-t1c-impl` worktree不可侵 / secrets非表示・非commit / application-specific語彙のCore流入禁止 / 赤CIでのmerge禁止。

## 5. レビュー履歴

| 日時 | レビュア | 結果 |
| --- | --- | --- |
| 2026-07-21 | Codex GPT-5.6 Sol high(rev1) | **NO-GO** P0=4/P1=10/P2=2 |
| 2026-07-21 | rev2(本書) | P0-4(R7↔Join循環)、P1-3(capability網羅)、P1-4(全provider)、P1-5(fragmentation分離)、P1-6(E2E順序)、P1-7(U1-U4昇格)、P1-8(R1-R9 closure)、P1-9(compliance非物理作業)、P1-10(CI前提化+packaging分割)を反映 |
| 2026-07-21 | Codex Sol high(rev2再レビュー) | **NO-GO** P0=1(T1cがC1に残存)/P1=1(B5受入条件不足)/P2=1(provenanceがuntracked未包含) |
| 2026-07-21 | rev3(本書) | C1からT1c除外しC3へ、B5受入条件明記、provenance manifest修正(recovery plan側) |
