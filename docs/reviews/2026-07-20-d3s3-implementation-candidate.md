# D3-S3 BLOB lifecycle implementation candidate — review memo

状態: **非規範 candidate memo**（Accepted ではない; GO ではない）  
対象: D3-S3 private evaluator / crossrow d3s3 append / production bridge / REP1 packing  
日付: 2026-07-20（原本）/ 2026-07-21 R28更新（repair chain through **R28**; this file is **R28 Accepted** pin — Sol xhigh r3 P0=0/P1=0 2026-07-21）  
base: `main` merge `39026aeb7415ada9654213332a087d388cab879e`

## Candidate status (current)

### Oracle pin（R28; **Accepted 2026-07-21** — Sol xhigh r3 P0=0/P1=0 + production/bridge evidence）

| Metric | Value |
| --- | --- |
| Authority path | `spec/vectors/domain-scan-crossrow-v1.json` |
| format | `ninlil-domain-scan-crossrow-v1-d3s3` |
| `vector_count` | **283** = frozen D3-S2 prefix **144** (exact invariant) + D3-S3 suffix **139** |
| suffix139 breakdown | **`rep1_l2` production 138** + **`formal_precheck` 1** |
| formal_precheck ID | `D3S3_M27_DUPLICATE_DIGEST_MATCH_CORRUPT` |
| `precheck_error` | `DUPLICATE_COMPLETE_KEY` |
| Canonical `content_sha256` | `0155b6929c2bb64396623cd75be283947b76c68d9f5d9578825ae5966b375639` |
| Full file raw SHA-256 | `8b17304f7edda04495aafa2e8f3a54bd7e57d5c147b8e62fca8a1b6b360740ed` |
| Vector body vs R27-Sol | **changed** (+3 Mode27 EF reason-closure CORRUPT: AWAITING cancel/CAPACITY, WAITING CAPACITY, DISPATCHING attempt0; EF AWAITING closed to {0}) |
| first144 vs `origin/main` | byte-for-byte object equality required (prefix144 exact invariant) — **verified exact** |
| Generator self-test | permanent RED matrix **a–r** + **R19…R24 D1** + **R25 STATE/CU fence** + **R26/R27 STATE product/EventFact lifecycle/CLI strict** + **R27 STATE matrix 29 positives + Mode27 4×4 lifecycle** + **R28 EF reason-closure 6+3prod** |
| Production typed diagnostic (cross-check only; not oracle authority) | family6 full accept when available (`ninlil_model_domain_validate_typed_record`) — not claimed as GO |
| D1 secondary differential (not production C) | see exact accounting table below |
| Production / bridge | **追従済み**（R28 r3: production Mode27 EF reason-closure adoption guard + two-lane bridge 139 green） |

**Production bridge green (R28 r3, two-lane 139 vectors). Not ADR Accepted. Not Stage 5 / D3 complete. Accepted/GO forbidden pending Sol re-review.**

### D1 secondary-authority differential (exact R27 pins; same R23/R24 corpus counts)

Secondary executable authority: shipped `spec/vectors/domain-store-v1.json`  
(`format=ninlil-domain-store-v1-d1b3o`, SHA `b809c223…`, count **1549**).  
Used family6 subtypes: **20 / 22 / 27 / 30 / 32 / 33 / 40 / 41 / 42 / 50**.

| Corpus class | Count | Independent gate result | Notes |
| --- | ---: | --- | --- |
| `typed_record` used-subtype OK | **74** | accept | fail-closed unknown expectation |
| `typed_record` used-subtype CORRUPT | **60** | reject | same-record D1 typed gate |
| `body_decode` used-subtype CORRUPT | **306** | wrap → reject | mechanical family6 envelope+key wrap; **checked=306** |
| `body_decode` non-applicable | **0** | — | all 306 wrappable under Normative key/envelope derivation; **no silent skip** |
| `body_roundtrip` used-subtype OK | **132** | accept | wrap → accept (anti false-reject) |

**body_decode checked by subtype (all CORRUPT → neg_ok):**  
`0x20:12`, `0x22:6`, `0x27:39`, `0x30:31`, `0x32:43`, `0x33:47`, `0x40:42`, `0x41:33`, `0x42:32`, `0x50:21` (sum **306**).

**body_roundtrip positives by subtype:**  
`0x20:2`, `0x22:1`, `0x27:29`, `0x30:15`, `0x32:11`, `0x33:11`, `0x40:7`, `0x41:30`, `0x42:16`, `0x50:10` (sum **132**).

### R24 boundary / CLI pins (retained) + R25/R26/R27 extensions

| Pin | Value |
| --- | --- |
| Boundary sweep total | **4380** = sum over baselines of `(exact_body_len + 1)` short/long forgeries |
| Boundary by variant | `20:670`, `22:225`, `27:646`, `30c:118`, `30m:131`, `32:799`, `33:227`, `40:553`, `41:379`, `42:331`, `50:301` |
| Type-contract cases | **6** (None/str/empty) → reason string, never raise |
| STATE legal positives | **28** family-specific closed branches (DS **23** + EF **5**) from docs/12+docs/13 reducers |
| Mode27 EF lifecycle matrix | **16** = 4 state-class × 4 spool; **7** permanent cross-row CORRUPT product vectors |
| CLI check exit2 matrix | `[]`, `null`, string, number, `{}`, malformed JSON, missing file, wrong `vectors`/row shapes, **bool/float vector_count**, nested float, NaN/Infinity/overflow |
| CLI generate exit2 matrix (R25/R26/R27) | existing path `[]`/`null`/string/number/malformed/object wrong shape/**short vectors**/float/**wrong first144** → exit **2**, one `error:` stderr line, no traceback, no success stdout; never adopt unvalidated first144 |
| CLI valid generate/check | exit **0**; no traceback |
| CLI grammar | exit **2** + one stderr line starting `error:` + empty success stdout + no traceback |

### R18/R27 formal_precheck / bridge lanes (honest)

| Lane | Count | Rule |
| --- | ---: | --- |
| `rep1_l2` | **135**（R27-Sol拡張後; 旧128はR27初版時点） | Exact call / Port grammar + REP1-L2 transcript equality |
| `formal_precheck` | **1** | Pre-generation **validator-only**: does **not** call production API; does **not** synthesize runtime `status` / `session` / `checkpoint` / `result` |
| zero Port on formal | — | Consequence of **bridge not calling production** (not a runtime product walk) |
| runtime duplicate defense | separate | **Nonzero-Port** product test — not the formal_precheck vector |
| bridge | **2-lane** | Unknown scope / count drift / silent skip = **RED** |
| R19–R27 D1 gate | all 136（R27-Sol拡張後; 旧129はR27初版時点） | Every suffix row locally D1-legal (no production C as oracle): profile catalog exact + BLOB full + **complete independent Normative D1** for used family6 **20/22/27/30/32/33/40/41/42/50** including R22–R27 closures; unknown subtype fail-closed |

### Sol high / Root review chain (honest chronology)

| Gate | Outcome (as recorded then) | What it meant |
| --- | --- | --- |
| Early docs-only BIND-WG / frontier / matrix repair | Historical **docs-only** Sol high “仕様GO” wording (P0/P1/P2=0 **for Normative text only**) | Spec text repaired for re-review; **not** oracle/authority/production/bridge/ADR Accepted |
| Pre-acceptance GET=0 BIND draft | **Withdrawn** | SHA `0658cbe0…` / 228/84 **not** authority |
| O1b oracle repair R5→R16 | Validator + self-test closure | Intermediate Proposed candidate only |
| Sol high after R15 | **NO-GO** P0=0 / **P1=2** / **P2=1** | Closed in **R16**/**R17** |
| R18 candidate pin | **Proposed** | total269 / prefix144 / suffix125 |
| Sol high on R18 | **NO-GO** | rep1_l2 fixtures must be D1 same-record legal |
| R19 candidate pin | **Proposed** | Independent D1-legality gate |
| Sol high on R19 | **NO-GO** | incomplete BLOB/ANCHOR/RC/CELL; trailing false-green |
| R20 candidate pin | **Proposed** | Partial complete D1 closures |
| Sol high on R20 | **NO-GO** | production typed 484/490; EventFact/CANCEL incomplete |
| R21 candidate pin | **Proposed** | Claimed complete independent Normative D1; typed 490/490 diagnostic |
| Sol high on R21 | **NO-GO** | revision; CELL trust/stage/RAW; INGRESS disposition/empty; RC token matrix |
| R22 candidate pin | **Proposed** | R21 residual repair + typed differential pos74/neg60 |
| Sol high on R22 | **NO-GO** | ORDERED_INGRESS cancel kind/family; CELL zero TX raw; BLOB owner identity length-only; body_decode silent skip; RAW MATERIALIZED optional baseline |
| R23 candidate pin | **Proposed** | R22 residual independent D1 authority repair |
| Sol high on R23 | **NO-GO** | TRANSACTION_STATE enum-only (READY+SATISFIED / TERMINAL+NONE false-green); EVIDENCE_CELL/CANCEL_STATE/DELIVERY empty body `struct.error`; CLI `check []` AttributeError exit1 traceback |
| R24 candidate pin | **Proposed** | R23 residual STATE partial matrix + body-length prechecks + CLI check-only |
| Sol high on R24 | **NO-GO** **P1=2 / P2=1** | See R24 Sol high findings below |
| R25 candidate pin | **Proposed** | R24 residual full STATE product + Mode27 lifecycle + CLI generate + COMMIT_UNKNOWN fence; content `bb56954f…` / raw `997f64e5…` |
| Sol high on R25 | **NO-GO** | See R25 Sol high findings below |
| R26 candidate pin | **Proposed** | R25 residual true STATE closed product + Mode27 EventFact full rebuild + generate/check strict fail-closed; content/raw SHAs above |
| Root QA on R26 | **NO-GO residual** | See R26 Root QA residual findings below |
| R27 candidate pin | **Proposed** | R26 residual: full STATE matrix re-extract from docs/12+docs/13 reducers + Mode27 3×4 lifecycle permanent; vector body object-identical; this memo |
| R28 candidate pin | **Proposed** | R28 r3: EF state-dependent reason closure (EF AWAITING={0}; EF WAITING excludes CAPACITY_EXHAUSTED(11); EF DISPATCHING attempt≥1) in oracle classifier + production adoption guard; Mode27 **4×4=16** lifecycle; +3 EF reason-closure CORRUPT vectors; counts **283=144+139** (production 138 + formal 1); content `0155b692…` / raw `8b17304f…`; **production/bridge 追従済み (two-lane bridge 139 green)** |
| Sol / production / bridge re-review | **Sol pending** | production/bridge **追従済み (R28 r3, bridge 139 green)**; Sol re-review required; **Accepted / GO forbidden** until complete |

#### R24 Sol high NO-GO details (closed by R25)

| Finding | Class | R25 repair (no R16–R24 weaken) |
| --- | --- | --- |
| TRANSACTION_STATE incomplete product false-greens: READY+deadline MET; Event-only PARKED+PENDING; TERMINAL SATISFIED/EXPIRED/UNKNOWN+PENDING; SATISFIED+APPLICATION_FAILED; WAITING+generated-zero UNSUPPORTED_FAMILY; OPERATOR_DISCARDED reason + discarded=0 | **P1** | Full family×state×outcome×deadline×reason×park/discard/dependent closed product from docs/12 §4.4 + public snapshot table + docs/17 body; family via `deadline_verdict` NA discrimination; generated-zero prohibition; discard bijection; 17 legal positives; exhaustive RED cases; mutations keep mirrors/envelope/key/digests valid |
| Mode27 lifecycle classifier used only `explicitly_discarded!=0`; hist fixture mutated DS into discard shape | **P1** | Normative lifecycle: active requires manifest; released/terminal requires man absent. Classifier uses decoded state/outcome/family + Event spool ACTIVE/PARKED vs RELEASED/DISCARDED. `D3S3_M27_HISTORICAL_ABSENT_OK` rebuilt as D1-legal DS TERMINAL+EXPIRED+MISSED+discarded=0 |
| CLI `generate` on existing `[]`/`null`/string/number → `probe.get` AttributeError rc1 traceback | **P2** | Shape validation before `.get`; documented exit2 + one `error:` stderr line; subprocess matrix for generate array/null/string/number/malformed/object wrong + normal deterministic generate |
| Oracle wrong on drive-time COMMIT_UNKNOWN fence (production correct): docs/17 §15.11.5 map+fence_pending; finalize via §18.14.19.11 | **contract correction (not weaken)** | Drive-time get/iter_open/iter_next COMMIT_UNKNOWN sets `fence_pending=1`; no in-drive cleanup; finalize rollback OK then close H1 once, reopen_required=1, final fence_pending=0, sticky retained, cleanup null, adopted0. Five expected vectors regenerated green; permanent self-tests pin all five + non-CU natural no fence |

#### R25 Sol high NO-GO details (closed by R26)

| Finding | Class | R26 repair (no R16–R25 weaken; docs/12 Normative authority) |
| --- | --- | --- |
| TRANSACTION_STATE product incomplete: UNKNOWN outcome/reason mapping wrong; EFFECT_POSSIBLE_EVIDENCE_MISSING(69) on FAILED false-green; CANCEL_PENDING_REMOTE_FENCE(86) on terminal CANCELLED; REQUIRED_EVIDENCE_MET(64) on AWAITING; EventFact terminal EXPIRED/CANCELLED false-green; cumulative/evidence dependent fields weak; positives not all family-correct | **P1** | Truly closed family×state×outcome×deadline×reason×evidence×dependent product: UNKNOWN includes 69; FAILED excludes 69; 86 AWAITING-only; 64 terminal SATISFIED-only; EF forbids EXPIRED/CANCELLED; cumul≥attempt_in; has_late⇒latest≠0; TERMINAL+SATISFIED⇒latest∈1..4; **18** legal positives; permanent false-green + false-red mutation self-tests |
| Mode27 EventFact fixtures only promoted ANCHOR (STATE remained DS-shaped; avd/pvd mismatch; lifecycle not exact receipt/discard matrix) | **P1** | Full EventFact rebuild: family-correct STATE (ddl=NA, retry/es_rev), matching `anchor_value_digest` + common PVD, matching spool revision/body. Lifecycle exact: nonterminal+ACTIVE/PARKED→LIVE; terminal receipt+RELEASED→HISTORICAL; terminal audited discard+DISCARDED→HISTORICAL; else CORRUPT. Permanent vectors `EF_HISTORICAL_RECEIPT_OK` / `EF_HISTORICAL_DISCARD_OK` / two CORRUPT cross-pairs + classifier/product self-tests. DesiredState terminal hist retained |
| CLI `generate` adopted unvalidated first144; weak nested/bool/float rejection | **P2** | generate fail-closed rc2 one `error:` line on scalar/non-object, non-list vectors, non-object elements, malformed rows, bool/float/nonfinite, wrong first144 authority — never adopt unvalidated first144; exact canonical authority before reuse |
| CLI `check` int-coerced bool/float | **P2** | Strict-type JSON integers (no bool/float coerce); reject float/nonfinite/overflow + malformed nested shapes rc2 one error no traceback; permanent CLI matrix |

#### R27-Sol Sol high intermediate residual (closed)

| Finding | Repair |
| --- | --- |
| STATE 22/20 false-red; WAITING 69/80/82/129 false-green | re-asserted permanent positives/REDs (matrix closed) |
| Mode27 missing family/avd/pvd/rev/state×park cross-row (7 false-greens) | `o1a_mode27_cross_row_ok` in classify+SELECT_SETUP; 7 product vectors; 4×4 lifecycle |
| generate adopts suffix rows={}/vector_count=true | full-document shape+int schema before adopt; exit2 |
| check nested faults_expected_used=false / u32 overflow exit1 | closed known-integer nested schema; input-shape exit2 |

#### R26 Root QA residual NO-GO details (closed by R27)

| Finding | Class | R27 repair (no R16–R26 weaken; docs/12+docs/13 Normative authority) |
| --- | --- | --- |
| DesiredState TERMINAL FAILED reason TARGET_UNAUTHORIZED(22) legal but rejected | **P1** | FAILED exact set from docs/13 Disposition matrix: {22, 70, 80, 128} |
| Clock uncertainty EXPIRED+reason20 and OUTCOME_UNKNOWN+reason20 legal but rejected | **P1** | EXPIRED={65,66,20}; UNKNOWN={69,20} (129 AWAITING-only); ddl INDETERMINATE for 20 |
| WAITING incorrectly accepts terminal-only reasons 82/83/69/129 etc. | **P1** | WAITING exact retry-window set only: {11, 85, 128, 130, 132} |
| AWAITING missing effect-possible APPLICATION_FAILED(128)/OUTCOME_UNKNOWN(129) | **P1** | AWAITING={0, 68, 83, 86, 128, 129} |
| REQUIRED_EVIDENCE_LATE(65) treated as SATISFIED | **P1** | docs/13 PROVEN_LATE → EXPIRED+65; SATISFIED={64} only |
| CANCEL_AFTER_EFFECT(83) treated as terminal CANCELLED | **P1** | 83 AWAITING-only; CANCELLED={82} only |
| Mode27 EventFact spool cross-pairs incompletely enumerated | **P1** | Permanent self-test 3 state-class × 4 spool = 12; receipt+DISCARDED / discard+RELEASED / nonterm+DISCARDED RED |
| Mere individual reason patches vs closed matrix | **process** | Full family×state×outcome×reason×deadline×evidence×dependent re-extract; docs/17 explicit closed sets 矛盾0 with docs/12/13 |

**Do not read any historical “docs-only GO” row as current completion of oracle, production Core, bridge, or ADR Accepted.**  
**Do not claim R23, R24, R25, or R26 completed D1.** R21–R26 were each Sol high / Root residual **NO-GO**. R27 is **Proposed only**.

### What R14–R27 closed in the independent generator (validator/self-test)

| Round | Invariant (summary) |
| --- | --- |
| R14 | Formal `faults` 0\|1 exact-binds single natural Port event; SELECT_SETUP realized typed/decode stop |
| R15 | G GET **storage_status** fixture presence column (OK/NOT_FOUND) |
| R16 | `port_trace` / `faults` strict JSON arrays; no falsy→`[]` coercion |
| R18 | suffix125 split; formal pre-generation validator-only; 2-lane bridge RED; prefix144 exact |
| R19 | Independent D1-legality gate on **every** suffix row |
| R20 | Partial D1 closures (BLOB primary_id; ANCHOR digests; RC product; CELL material; exact body) |
| R21 | Claimed complete independent Normative D1 — **Sol high NO-GO** residual false-greens |
| R22 | Revision/CELL/INGRESS/RC false-green repairs + typed pos74/neg60 — **Sol high NO-GO** residual holes |
| R23 | R22 residual D1 authority repair — **Sol high NO-GO** (STATE matrix incomplete; empty-body raise; CLI []) |
| R24 | Partial STATE state×outcome + body-length prechecks + CLI **check** exit2 — **Sol high NO-GO** P1=2 P2=1 |
| R25 | Full TRANSACTION_STATE family×product (partial); Mode27 lifecycle classifier + DS TERMINAL hist; CLI generate shape exit2; COMMIT_UNKNOWN fence — **Sol high NO-GO** residual STATE/EventFact/CLI |
| R26 | Independent oracle repair (no production C oracle; no R16–R25 weaken): true STATE product attempt + Mode27 EventFact full rebuild + CLI strict — **Root QA residual NO-GO** on STATE matrix holes. Vector body SHA **changed** then. Counts **273=144+129**. |
| R27 | **Independent oracle/spec repair (no production C oracle; no R16–R26 weaken):** full TRANSACTION_STATE reachable public snapshot matrix re-extracted from docs/12+docs/13 reducers; STATE positives **28**; Mode27 lifecycle permanent **3×4=12**; CLI/COMMIT_UNKNOWN fence preserved. Vector body object-identical to R26 (content/raw SHAs unchanged). Counts **273=144+129**（当時; R27-Solでsuperseded）. |
| R27-Sol | **Mode27 EF cross-row拡張（`o1a_mode27_cross_row_ok` を classify+SELECT_SETUPへ; family/avd/pvd/rev/state×park）:** +7 Mode27 EF cross-row CORRUPT product vectors; 4×4 lifecycle; generate/check full-document shape+int schema。**Vector body changed vs R26/R27**: counts **280=144+136**（production 135 + formal 1）; content `93edadc3…` / raw `1506f432…`（冒頭表pin）. **Production/bridge 追従は 2026-07-21 回収トランチ**（docs/work/2026-07-21-d3s3-r27-bridge-recovery-plan.md）. |
| R28 | **ADR-0015受入レビュー(Sol xhigh NO-GO P0=0 P1=1 P2=2)回収 (r3確定):** (P1-1) EventFact状態依存reason集合の閉包 — EF AWAITING={NONE(0)}（deadline/cancelなし ⇒ 68/83/86/128/129拒否; docs/13 §964/§1061/§1149, docs/12 §1758）、EF WAITING は CAPACITY_EXHAUSTED(11) を拒否（PARKED専用）、EF DISPATCHING は attempt_in_cycle≥1 下限。閉包はoracle分類器（`o1a_mode27_cross_row_ok`）とproduction Mode27採用guard（`run_select_setup_mode27`）で実施；D1 constructibility gateはEF行をconstructibleのまま保持（採用guardを識別的回帰試験可能にするため）。+3 Mode27 EF reason closure CORRUPT product vectors（family/cross-row通過、reason gateのみでRED: AWAITING+CANCEL_PENDING_REMOTE_FENCE / WAITING+CAPACITY_EXHAUSTED / DISPATCHING+attempt_in_cycle=0）＋恒久self-test RED（68/128/129含む6変異）。(P2-1) generate fail-closed: suffix row={} / value_hex欠落 / checkpoint閉鎖整数スキーマ（previous_key_length / last_carrier_key_len / event_start 等、bool/float/未知キーを任意depthで拒否）を exit2 で拒否＋CLI self-test。(P2-2) docs件数/SHA正規化（ADR 3×4=12→4×4=16; docs/17 283件・新SHA・bridge green）。**Vector body changed vs R27-Sol**: counts **283=144+139**（production 138 + formal 1）; content `0155b692…` / raw `8b17304f…`. **Production/bridge 追従済み（two-lane bridge 139 green）.** |

Permanent self-test: `R16 G schedule/status/fault/type exact RED ok (a-r)` + `R19…R24 independent D1-legality gate RED matrix ok` + `R25/R26/R27 COMMIT_UNKNOWN fence + Mode27 lifecycle pins ok` + `R24/R25/R26 CLI closed failure matrix ok` (generator).

## Historical note — Sol high docs-only gate (not current GO)

Earlier on this branch, after terminal/G-entry/first-outer Normative repairs, Sol high recorded a **docs-only** re-review outcome of **仕様GO（docs-only）, P0=0 / P1=0 / P2=0** for the **spec text** items listed below. That outcome is retained here as **history**. It never claimed oracle regen, production Port-trace match, bridge green, or ADR Accepted.

| Finding class | Spec text after that docs pass | Still open for implementation GO |
| --- | --- | --- |
| GET=0 BIND packing constructibility | **Repaired**: W/G/**WG**; withdrawn draft SHA `0658cbe0…` | production / Accepted |
| Mode30 frontier / nontermination / latch | **Repaired** §18.14.9.3 + BIND-entry once-only empty BLOB-manifest frontier | production |
| PASS_INTERNAL public counter freeze | **Repaired** §18.14.9.5 / §18.14.19.3; lex-only visit | production hook order |
| Closed next-unit matrix / reopen / G entry / FAILED capture | **Repaired** §18.14.19.3–.4 | production / Accepted |
| Docs flag label at value `0x15` | **Renamed** docs-only to `F_BIND_REOPEN`（value/wire unchanged） | — |

## Scope present on code surface (not “closed / green”)

| Item | Status |
| --- | --- |
| Private `domain_store_d3s3.h/.c` context sizeof **754** / align **1** / ceiling **768** | present |
| Outer aggregate pin **9920** | present |
| modes **27..30**, `k₃=4`, 1 session = 1 mode = 1 `READ_ONLY` txn | present |
| `begin_profiled_d3s3` / `d3s3_drive` / H1 `on_row` / H2 `on_exhausted` | present; **not** claimed REP1-L2 field equality |
| KEY_DIGEST digest-match SCAN single arm（reverse / rebuild exact_get 禁止） | production path present |
| Mode30 companion matrix / BIND reverse / sequential BIND phases | present; must match §18.14.9.3 frontier/latch |
| independent generator / emit-c / candidate JSON 283 | **R28 Proposed** oracle candidate; **not** Accepted |
| production exact bridge | **green** (R28 r3 two-lane bridge 139 vectors; production 138 + formal 1) |

## Measured product (honest)

| Metric | Value |
| ---: | --- |
| Last pre-acceptance withdrawn draft vector_count | **228** total / d3s2 prefix **144** / d3s3 suffix **84** |
| Withdrawn draft full SHA (do not pin GO) | `0658cbe092313e19dbb4498dcd5a786517651cb984ddfc7f97f2a47b372cf36f` |
| Current R28 oracle candidate | **283** / prefix **144** / suffix **139** = production **138** + formal **1** / content `0155b692…` / raw `8b17304f…`（冒頭表と一致; R28 r1/r2 283 content `e2c057e8…` / raw `9d6bb6ae…`、R27-Sol 280=144+136 content `93edadc3…` / raw `1506f432…` は superseded） |
| D1 secondary differential | typed **74/60**; body_decode **306 checked / 0 non_app**; body_roundtrip **132** |
| R24/R27 boundary sweep | **4380** total; all subtypes/variants >0 |
| STATE legal positives | **28** (DS 23 + EF 5) |
| Mode27 EF lifecycle cells | **16** (4×4) |
| Production bridge under REP1-WG | **green** (R28 r3 two-lane bridge 139 vectors) |
| Older memo “62 suffix / constructible closed scope” | **obsolete / incorrect** as completion evidence |
| R26-era content/raw SHA pair | **same as R27 vector body** (R27 gate-only); do not treat R26 matrix as complete authority |
| R25-era candidate SHAs `bb56954f…` / `997f64e5…` | **superseded** by R26 body |
| R24-era candidate SHAs `12d1729e…` / `1b210e29…` | **superseded** by R25 |
| R23-era candidate SHAs `bdaed45d…` / `3aeb1b02…` | **superseded** by R24 |
| R22-era same SHA pair as R23 | historical intermediate (R22/R23 NO-GO) |
| R21-era same SHA pair | historical intermediate (R21 NO-GO) |
| R20-era candidate SHAs `e9d7fe7d…` / `43508808…` | **superseded** |
| R19-era candidate SHAs `d6905bdf…` / `7e8a543d…` | **superseded** |
| R18-era candidate SHAs `6f142a6e…` / `a1276cba…` | **superseded** |

### §18.14.15 anti-false-pass 1..17 — inventory anchors (not GO)

| Case | Exact production vector ID (primary anchor) |
| ---: | --- |
| 1 | `D3S3_M27_SCAN_NOT_REVERSE_OK` |
| 2 | `D3S3_M27_LIVE_ANCHOR_MAN_CHUNK_OK` |
| 3 | `D3S3_M30_RECEIPT_EMPTY_BLOB_OK` |
| 4 | `D3S3_M30_CROSS_DELIVERY_DIGEST_CORRUPT` |
| 5 | `D3S3_M30_DISP_NONEMPTY_BLOB_CORRUPT` |
| 6 | `D3S3_M30_CELL_BYTE_MISMATCH_CORRUPT` |
| 7 | `D3S3_M30_ORPHAN_MANIFEST_0RR_CORRUPT` (+ `D3S3_M30_SAME_DELIVERY_2RR_OK`) |
| 8 | `D3S3_M30_SAME_DELIVERY_2RR_OK` |
| 9 | `D3S3_M27_ORPHAN_CHUNK_CORRUPT` (also M28/M29/M30) |
| 10 | `D3S3_M30_MISSING_CANCEL_CORRUPT` (+ RECEIPT/DISP/CUSTODY missing companions) |
| 11 | `D3S3_M27_DUPLICATE_DIGEST_MATCH_CORRUPT`（formal_precheck lane: `DUPLICATE_COMPLETE_KEY`; runtime defense is separate nonzero-Port） |
| 12 | `D3S3_M28_SEMANTIC_DIGEST_MISMATCH_CORRUPT` |
| 13 | `D3S3_M27_OWNER_PVD_MISMATCH_CORRUPT` |
| 14 | `D3S3_M28_DUAL_VIEW_PAYLOAD_NONEMPTY_OK` |
| 15 | `D3S3_M29_RESULT_CACHE_MISSING_CORRUPT` |
| 16 | `D3S3_M27_EMPTY_PROFILE_PRODUCT_OK` (four-session empty product set) |
| 17 | `D3S3_M27_MISSING_CHUNK_CORRUPT` (+ zero/hist/stream negatives) |

## Explicit non-claims

- **Not Accepted**（本 memo は R27-Sol Proposed candidate のみ）
- **Not GO** for production / bridge / ADR / security / Stage 5
- **R21 was Sol high NO-GO** — do not treat R21 as closed authority
- **R22 was Sol high NO-GO** — do not treat R22 as closed authority
- **R23 was Sol high NO-GO** — do not treat R23 as completed D1 / closed authority
- **R24 was Sol high NO-GO** — do not treat R24 as completed D1 / closed authority
- **R25 was Sol high NO-GO** — do not treat R25 as completed D1 / closed authority
- **R26 was Root QA residual NO-GO** — do not treat R26 as completed D1 / closed authority
- Historical **docs-only 仕様GO** is **not** current oracle/production completion
- D3 overall / D3-S4..S12 / Stage5 D3 bind / public Runtime / D4 / ESP / HIL / V1 **not complete**
- Full matrix green / residual 0 / production Port-trace match **not claimed**
- Withdrawn GET=0 BIND draft **not** authority
- Public API/ABI / wire / D1 codec / Port ABI **unchanged** by this oracle-candidate turn（generator/docs only; no production C edit in this R27 oracle lane）
- Dual-bound S1+S2+S3 / one-baseline-all-four **forbidden** and not claimed
- formal_precheck is **not** a REP1-L2 transcript vector and **not** production GO evidence
- R19–R28 do **not** weaken D1 or production validation; production C is **not** the oracle authority (typed diagnostic is cross-check only)
- **Production / bridge 追従済み**（R28 r3: Mode27 EF reason-closure adoption guard + two-lane bridge 139 green）

## Residual

**Open (honest):**

1. **Sol high re-review** of R28 oracle candidate + Normative R13–R28 grammar/fault/type/lane/D1-legality/CLI/fence/lifecycle/STATE matrix text.
2. **Production / bridge follow-up** to R27/R28 TRANSACTION_STATE closed product + Mode27 lifecycle matrix + EF reason closure — **done in R28 r3** (two-lane bridge 139 green).
3. **Production Core** W/G/WG + lex-only INTERNAL + reopen exact + field-for-field bridge.
4. **Two-lane bridge** evidence (`rep1_l2` exact Port; formal_precheck validator-only; RED on unknown scope/count drift/silent skip).
5. **ADR-0015 Accepted** only after independent review P0=0 **and** production/bridge evidence — not claimed here; **Accepted/GO forbidden**.

Self-review author: main-spec implementer. Not Normative.
