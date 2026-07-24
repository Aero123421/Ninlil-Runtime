# Ninlil V1 LAB 完成計画（完成定義修正版）

状態: rev2（Sol high r1 NO-GO P0=6/P1=4 を反映; 再レビューへ）
orchestrator: Fable。旧 master plan（2026-07-21）の §0 は本書で **V1 LAB / V2 に分割**される。

## 0. 完成定義（root 指示の凍結）

- **V1 = Ninlil V1 LAB**: 24–48 時間で**機能完成**。LAB 縦切り 10 項目をコード・テスト・文書・E2E で完成し、**stub / TODO / 未接続経路を残さない**。
- **V1 必須の基本品質**: ACK、再送、重複排除、timeout、CRC/認証境界、再起動、false success 禁止、bounded/fail-closed。
- **V2 へ延期**: 圧倒的堅牢性、全 crash 境界、巨大 oracle、極端な障害網羅、relay、multi-parent、完全 wire fragmentation/reassembly/custody、production 法規認定、全障害の形式証明。
- 名称: **Ninlil V1 LAB**（docs/05 の `LAB`/`LAB_ONLY` credential profile・隔離環境前提）。

## 1. V1 LAB 縦切り 10 項目

（注: root 言及の「先ほどの LAB 縦切り 10 項目」の原文リストは本 repo に見当たらないため、master plan §0/§2 を root の V1/V2 分割基準で射影した本リストを正とし、相違があれば root 訂正を反映する。）

1. **Store/再起動正当性（V1-LAB durable allowlist profile; Sol P0-1 是正案 2）**: 既存 D1/D2/D3-S1..S3 + Stage5 recovery writer + POSIX SQLite を**完成昇格**し、durable evidence→restart→再開の E2E。**V1-LAB durable profile = record kind・state・operation の closed allowlist** を固定: writer は D3-S1..S3 で完全検証できない row/state を生成せず（項目 2–9 が allowlist 外を生成しない構造 gate 付き）、recovery は allowlist 外/unknown/corrupt/mixed を publication 前に必ず拒否（成功 evidence 0）。D4 convergence は **V1 allowlist 内 operation 分だけ実装**。restart 負例（unknown/corrupt/mixed/COMMIT_UNKNOWN）を受入条件に含む。D3-S4..S12 の scanner 網羅と D4 全域は V2。
   **ESP durable success 禁止（Sol P0-5）**: V1 の成功可能な durable E2E は **POSIX SQLite に限定**。ESP は HIL attestation の無い build では FULL/custody success・positive ACK/Receipt・payload release を**構造的に発行不能**（exact reject または COMMIT_UNKNOWN へ閉じる）。ESP success symbol/call path 0 の link/source gate + readback 一致でも success へ昇格しない負例を受入条件へ。「ESP provider 完成昇格」= software 実装完了 + fail-closed availability 判定の意味に限定。
2. **B1 public Runtime body**: 14 API 正本 semantic、`runtime_step`、service_register/submit/cancel/event_resume|discard、durable delivery path（計画は PR #111 merge 済みの B1 план準拠）。
3. **B2-LAB provider 統合**: POSIX 全 provider factory/ownership/shutdown/restart + ESP-IDF は **target build + 主要 provider の host 検証**まで（HIL は従来どおり残件明示）。restart E2E 含む。
4. **B3 論理 capability 層**: priority/deadline/retry 本経路 + logical payload/fragment capability + reservation（wire frag は V2）。simulated bearer 検証。
   **V1 payload admission 上限（Sol P0-4）**: 各 bearer に exact single-frame/application 上限を固定（U6=926B 等）。上限内のみ admit; 超過は ownership 取得・transaction 作成・partial write・success evidence 全て 0 で `REJECTED`（または実装済み別 bearer への決定的 route）。`max-1/max/max+1`・再起動・partial-apply=0 を統合 E2E で実証。上限を満たせない BoundedTransfer use case は V1 で unsupported と public 明示。
5. **B4 PC 間 direct 1-hop E2E**: 2-process loopback bearer で submit→ACK→deliver→evidence→restart→重複排除/再送/timeout の E2E（V1 基本品質の実証舞台）。
6. **B5-LAB application capability 群**: 複数 ServiceDescriptor 登録/分配、LatestState、MeasurementBatch、BoundedTransfer(partial-apply=0)、ConfigRevision、target resolver の基本経路（**counter-offer は V1 では生成もせず reserved/unsupported**; 生成/保存/acceptance 込みの実装は V2）。
7. **C2-LAB Join/Attachment**: M4 handshake、install token mint、site membership を LAB credential で。C1 の必要 stateless primitive 閉包含む。
8. **C3-LAB secure wire 基本 + context lifecycle（Sol P0-2）**: T1c token consume→authenticated context install、counter/nonce/AEAD/replay/durable admission（CRC/認証境界=V1 必須）。W1/L1 基本。**V1-LAB context lifecycle を閉じる**: Hop/E2E の送受**両方向**、DATA/ACK lane、freshness/epoch fence、counter burn、replay state、clean restart、COMMIT_UNKNOWN restart。M5 は V1 では実装せず、**restart 時は必ず fresh M4 handshake へ戻り、旧 context を fence して nonce/key を再利用しない代替遷移を正本化**（ALL_PROPOSED 後の同 token/secret 再注入禁止を維持）。両 endpoint の restart E2E を受入条件へ。極端故障網羅は V2。
9. **C4/C5-LAB USB + radio software path**: USB Controller/Cell Agent（U 系完成昇格; host simulation）、SX1262 software path（R1..R9 closure の software 経路 + RX authentication/replay; host SPI/radio simulation）。実 RF/HIL は残件明示。
10a. **C6-LAB enforcement（Sol P0-6 分割/P1-3）**: LAB_ONLY compliance profile enforcement。**V1 が送信可能な全 frame type の exact-set manifest** を作り、各 type が R5 bind→R2 permit→R1 consume→R9 SPI の sole edge を通る link/call-graph gate。範囲外 profile・期限切れ assignment・clock uncertainty・permit failure は SPI TX 0。「国内実運用可能」と表示しない態様（production 認定は V2）。**項目 9 の送信可能化より前に完了**。
10b. **統合 E2E gate + packaging/docs/RC（Sol P0-3/P1-4）**:
   - **統合 gate（RC 前必須）**: host 上で単一 topology `public submit → family/admission/reservation → durable queue → USB Controller/Cell Agent software path → W1/L1 AEAD → R9 host SPI/radio simulation → peer RX auth/replay → dedup/service delivery → durable evidence → authenticated ACK/Receipt → source outcome` を一つの実行で通す。同 gate で ACK loss / data duplicate / reorder・replay / timeout / retry budget 枯渇 / 各 process restart / CRC fault / auth fault / storage fault を注入し、**false success 0・bounded termination・範囲外 fail-closed** を確認。test-only direct loopback/bypass symbol が成功経路へ入らない structural check 付き。
   - packaging: LICENSE/NOTICE/third-party notices、配布物 manifest、**再現可能な外部 consumer build/install smoke**。SBOM/signing は V2（V1 RC の非主張として明記）。examples（Controller/Cell/Display/Leak 相当 host simulation）、利用者/開発者 docs、**V1 LAB RC tag**（残件=物理実機系 + V2 roadmap を証拠付きで限定）。

**B5-LAB family 最小受入（Sol P1-1）**: family ごとの最小状態遷移+負例の表を項目 6 の受入 artifact とする（LatestState=stale generation 非適用 / MeasurementBatch=retention・aggregation / ConfigRevision=stage・validate・commit・rollback / target 別 Outcome・決定的 aggregate）。**counter-offer は V1 では生成もせず reserved/unsupported**（M1a 正本の規則に整合; acceptance 込みの実装は V2）。
**ESP provider matrix（Sol P1-2）**: platform provider 全 catalog に `implemented / LAB unavailable fail-closed / V2` + factory/owner/shutdown/restart/fault test/target link の行を持つ matrix を受入 artifact とする。`LAB unavailable` は Runtime init または該当 admission で明示 reject（stub success 禁止）。

各項目の受入 = コード + テスト（正常系 + V1 基本品質の負例）+ 文書 + E2E 接続、stub/TODO/未接続 0。CI（Linux/macOS + ESP-IDF target build + ASan/UBSan）green は維持。

## 2. V2 roadmap（延期リスト; V1 RC 文書に添付）

- D3-S4..S12 scanner 網羅（A2-c/d production bridge、A3、A4 深部）。**A2-b oracle は本日時点の 200-vector 状態で freeze**（20+ commits; Sol r7 網羅レビューは V2 再開時）。
- relay（C7）、multi-parent（C8）、完全 wire fragmentation/reassembly/custody（C5 深部）。
- production 法規認定（C6 本経路、RegulatoryProfile signer/配布/revocation の production 運用）。
- 全 crash 境界・極端障害網羅・形式証明、D1 full security audit、mutation 拡充（D2 深部）。

## 3. 実行順序（critical path; 24–48h; Sol P0-6 merge barrier）

並列作業は **pure codec/model/fixture の candidate 作成に限定**し、完成受理は以下の barrier に従う（barrier 前は candidate 扱い; stub/fake provider/test credential を通る経路を完成扱いしない）:

```
1 + 2 + 3 ──────────────→ 7 ──→ 8
1 + 2 + 3 + 4 ──────────→ 5
1+2+3+4+7+8+10a ────────→ 9
5 + 6 + 9 ──→ 統合E2E gate（10b 内）──→ 10b packaging/docs/RC
```

- Lane 併走は candidate 生成まで: Lane A=1→2→3、Lane B=4→6 の codec/model、Lane C=7→8 の primitive/fixture。**受理は barrier 順**。
- 項目 10a（LAB_ONLY enforcement）は項目 9 の送信可能化より**前**。

worker: Cursor Composer 2.5 主軸（Qwen 停止中; 復旧後も進行中 unit の green/commit まで待って切替）。レビュー: 各項目の計画は Sol high 1 round（P0 のみ解消必須へ緩和; P1 は V1 内対処 or V2 記録を選択可）、実装 diff は Grok または Sol 1 round。**巨大網羅レビュー（Sol r7 級）は V1 では行わない。**

## 4. 直近アクション

1. 進行中 B6（A2-b 小口負例）を green checkpoint で commit し、**A2-b を V1 スコープで凍結**（B7/Sol r7 は起動しない）。
2. 本計画の Sol high レビュー（P0 解消のみ必須）。
3. Lane A 項目 1 の worker dispatch（既存候補の完成昇格から）。
