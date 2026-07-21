# ADR-0015: D3-S3 Reference Execution Profile v1（REP1）

状態: **Accepted（2026-07-21）** — R28 oracle 283 + production実装 + two-lane bridge 139 green + Sol xhigh r3 P0=0/P1=0  
提案日: 2026-07-20  
受入日: 2026-07-21（Sol xhigh r3; docs/work/2026-07-21-adr0015-review-r{1,2}.md + r3ログ）  
非主張: D3-S3 implementation complete、production bridge green、D3 complete、Stage 5、
public Runtime、ESP-IDF/hardware、security audit、REP1 production C bit-equality evidence、
ADR Accepted

## Context

D3-S3a（docs/17 §18.14）は BLOB lifecycle の意味論を閉じた。O1a は final status を独立導出できる。
exact Port transcript（O1b）には、Port event 入力/出力キー分離、NATURAL fault closed set、
phase/substate/mask の numeric tuple、Mode28 total の lossless pin が必要だった。

Independent repair review round 2 は next-unit / fault / capacity 等を残件とした。

**Sol high NO-GO follow-ups（docs repair rounds）:**

1. Pre-acceptance BIND pure-W **GET=0** packing was non-constructible under 754 / no full-ID set → withdrawn draft SHA; replaced by closed **W / G / WG**.
2. Mode30 frontier / same-man loop ambiguity → exact first-`>`-frontier select + boolean latch `observed_live` 0/1 + frontier promote only on RR success; **BIND-entry once-only reset** empties BLOB-manifest frontier after SELECT→BIND so RR carrier keys never poison man selection（docs/17 §18.14.9.3）。
3. PASS_INTERNAL public counter re-increment language → corrected: freeze `ok_row_count` / `current_domain_key_count` / family14 / profile diagnostics; visit-before-GET is **lex-only**（§18.14.9.5 / §18.13.5）。
4. BIND_CHUNK complete-key identity from get response → removed; GET value-only; digest equality on request/rebuild path.
5. Next-unit uniqueness → closed allowed non-terminal `(phase,focus_mode,semantic_pass)` matrix without overlapping mode rows; separate terminal failure-capture table; `pass_kind` drive-entry legality + `focus_mode∈{27..30}`; absent/wrong ⇒ INVALID_STATE before Port.
6. Reopen grammar → every W/WG requires `iter_live=1` before Port; NEED_REOPEN=1 ⇒ exact close+open; NEED_REOPEN=0 ⇒ neither; NEED_REOPEN=0+iter_live=0 or NEED_REOPEN=1+iter_live=0 ⇒ INVALID_STATE.
7. **O1b-R1 P0:** SELECT phase2/sem0 must be pure **W**（no mid-walk setup get）。Mode27 / Mode29 APPLICATION_FIRST companion GETs are a separate **G** unit phase2/`semantic_pass=6`（SELECT_SETUP）。WG remains BIND-only。

## Decision

1. **REP1-v1** の詳細正本は docs/17 **§18.14.19**（本 ADR は要約）。L1 BIND 義務は **§18.14.9** と joint。
2. **命名:** **REP1-L1**（semantic）/ **REP1-L2**（transcript）。private build は REP1-L2 受入代替不可。
3. **Formal 入力:** profile-exact only; ordered `rows[]`; fault array length **0 or 1**;
   fault object exact keys `{op,on_call,status,shape}` with `shape="natural"`;
   `status ∈ {NO_SPACE,IO_ERROR,CORRUPT,COMMIT_UNKNOWN,BUSY,UNSUPPORTED_SCHEMA}`;
   `op ∈ {get,iter_open,iter_next,rollback}`;
   floors: `get.on_call≥18`, `iter_open.on_call≥2`, `iter_next.on_call≥1`, `rollback.on_call=1`。
   Formal suffix NATURAL authority must realize the exact **24-pair Cartesian**
   `{get,iter_next,iter_open,rollback}×{NO_SPACE,IO_ERROR,CORRUPT,COMMIT_UNKNOWN,BUSY,UNSUPPORTED_SCHEMA}`
   as executable vectors（set equality; self-tests alone insufficient; O1b-R2）。
   `N≤UINT32_MAX-1` and every derived u32/u64 call/event/counter value must be representable without wrap; otherwise the vector is ill-formed。
4. **Port event:** closed keys include `request_key_hex` / `request_key_length`。
   GET only carries request key; GET output key fields always `""/0/0`。
   ITER_NEXT only uses `key_hex/key_capacity/key_length` as output descriptor。
   Other ops: both request and output key systems exact `""/0`（capacities 0）。
5. **Capacities:** non-zero only GET `value_capacity` and ITER_NEXT `key_capacity`/`value_capacity`。
6. **`returned_status`:** Runtime symbol closed enum in §18.14.19.2。
7. **Mode28 pin:** `focus_id16[0..7]=view_a_total_length u64be`,
   `[8..15]=view_b_total_length u64be`; full u64 lossless; zero view ⇒ 0; layout 754 unchanged。
   At phase-9 PREFIX G entry, both pins must checked-fit u32 before any Port event; oversize ⇒ CORRUPT/phase14, otherwise exact u32be semantic feed。
8. **Control vocabulary:** `phase` 0..14 exact; `pass_kind` 0/1; Mode28 `focus_sub` 0/1;
   `semantic_pass` 0..6 exact（7..255 invalid; **6 = SELECT_SETUP_G_PENDING**）。For non-terminal phase 1..12,
   next unit is uniquely determined by the closed `(phase, focus_mode, semantic_pass)`
   matrix in §18.14.19.4; absent tuple ⇒ INVALID_STATE before Port。COMPLETE/FAILED
   are no-drive terminal checkpoints governed by the separate closed terminal table。
   Phase2/sem0 is pure SELECT **W**（GET 0）。Phase2/sem6 is SELECT_SETUP **G**（Mode27; Mode29 APPLICATION_FIRST）。
9. **OK exits:** every success publishes numeric tuple  
   `(session.state, phase, pass_kind, focus_sub, semantic_pass, flags, count_mask, binding_mask)`  
   using flag normal forms `0x00/0x03/0x09/0x11/0x13/0x15/0x43` only.
   Docs label for `0x15` is **`F_BIND_REOPEN`**（value/wire unchanged）。
   Transient `CARRIER_INSTALLED`/`MATCH_DUPLICATE` do not survive successful checkpoints。
10. **B5:** BASELINE W only（first `N`, resume `N+1`）。Forbidden on other W / every WG / every G。
11. **Session state:** successful true-exhaustion **W** and **WG** and following G stay `EXHAUSTED`;
    only B5 midwalk is `OPEN`。
12. **Failure exits:** FAILED/phase14 rules and finalize rollback fault order in §18.14.19.10–.11。
    Phase14 preserves the failing entry's `pass_kind` / `semantic_pass`: BASELINE
    failure is pass0/sem0; INTERNAL failure is pass1 and sem is mode/reachable-entry
    exact（Mode27/29: 0 or 6; Mode28: 0..4; Mode30: 0 or 5）。Terminal drive remains forbidden。
    Finalize close: `rollback_status != OK OR fence_pending != 0`。Rollback fault stores cleanup Storage status, never overwrites prior sticky, prior sticky wins result status, no-prior-sticky uses mapped cleanup status, and adopted is 0。
    Natural GET fault mid-**WG** is last Port event; residual `iter_next` forbidden; **lex-only** visit commit for the preceding OK `iter_next` remains; public counters stay frozen under INTERNAL。
13. **Micro-step（closed three kinds）:** one `d3s3_drive` = exactly one of **W**, **G**, or **WG**.
    - **W:** walk only（exact reopen prefix + `iter_next*` + terminal NOT_FOUND / B5）。No `exact_get`（includes SELECT pure W）。
    - **G:** closed exact_get burst only; `row_budget=0`（includes SELECT_SETUP / OWNER / CHUNKS / SEM_*）。
    - **WG（BIND only; not SELECT）:** exact grammar  
      `[if NEED_REOPEN=1: exactly one iter_close then exactly one iter_open], (iter_next OK [, exact_get if eligible])*, iter_next NOT_FOUND`  
      with exact eligible pairs / phase-local pin tables / post-get compares in docs/17 **§18.14.9.2–.5**,  
      lex-only visit-before-GET under PASS_INTERNAL freeze, Port-only inputs（no fixture `idx`）,  
      internal-hook-only get（no public callback reentrancy）。  
    Modes27–29 BIND_MAN and Modes27–30 BIND_CHUNK are **WG**. Mode30 BIND outer + RR-band are pure **W** with frontier + boolean latch.  
    Unit kind is schedule classification, **not** a new checkpoint schema field.  
    Shipped reference Core must implement this split and the numeric enums. Mapping tables are non-REP1 diagnostics only.
14. **Reopen / liveness exact:** every formal W/WG entry（including BASELINE）requires `iter_live=1` before any Port event。NEED_REOPEN=1 requires `iter_live=1` and emits close+open once each; NEED_REOPEN=1+iter_live=0 ⇒ INVALID_STATE before Port; NEED_REOPEN=0+iter_live=1 emits neither; NEED_REOPEN=0+iter_live=0 ⇒ INVALID_STATE before Port。Every G entry requires exact `session.state=EXHAUSTED && txn_live=1 && iter_live=1` under D2-S4 and performs no reopen。
15. **Mode30 BIND-entry init:** exactly once on SELECT-empty → BIND_MAN: zero BLOB-manifest frontier and selected peer/pins/latch per §18.14.9.3; preserve `focus_id16` and all unlisted fields; never re-init before each outer W。
16. **Handles:** begin `H1→T1`, 17 profile GET, `iter_open→I1`, void close, cleanup order,
    successful path retains H1。
17. **Checkpoint closure:** `peer_key` is not serialized but is Normative derived control state for BIND/Mode30。Request bytes are frozen only in Port events。`d3_peer_get_count` counts every post-profile GET attempt, including NOT_FOUND/fault **and BIND-WG gets**, and equals `port.get_count-17`。Sticky/cleanup fields use closed Runtime/Storage symbol sets and exact null convention。
18. **Memory:** context sizeof **754** / align 1 / ceiling **768** unchanged; full-ID set / heap / VLA / second txn / second iterator **forbidden**。
19. **Honest cost:** Modes27–29 BIND_MAN **O(N+M)**; BIND_CHUNK **O(N+C)**; Mode30 multi-walk RR-band cost stated honestly in §18.14.11。
20. **Why WG over repeated W→G:** preserves general-input L1 completeness with O(1) fixed pins and practical O(N) walks plus necessary gets, without exploding formal call columns or requiring offline fixture omniscience。

## Consequences

- **GET=0 BIND packing** is repaired in Normative text（W/G/WG）。
- **This docs pass** repairs Sol high spec findings: frontier/latch（including Mode30 BIND-entry empty BLOB-manifest frontier reset after SELECT→BIND）, INTERNAL counter freeze, closed non-terminal next-unit matrix, separate failure-capture terminal legality, exact G/W/WG liveness, and removal of the first-outer duplicate transition。
- Sol high / Root independent re-review after O1b-R1 found formal NATURAL fault **Cartesian gap**（10/24 pairs）→ **O1b-R2** 24-pair Cartesian; **O1b-R3** G preflight executable + returned-value typed CURRENT（domain_format/body_len/CRC/flags; no short forged NLR1）on all product GETs; BIND negatives re-homed to intended BIND units。
- **O1b-R5→R27-Sol oracle candidate (not C sizeof proof; not production GO; not Accepted):** every live pin/man key has an **executable** map to a §18.14.12 `(offset,size)` slot; simultaneous unequal overlaps reject; pin==context for that slot. Projections release on SELECT sem0 / BIND / COMPLETE **and on sticky FAILED** (before drive-end assert) with product SHA abandoned. **R12–R18** as prior rounds. **R19–R25:** independent D1-legality progression — each was Sol high **NO-GO** (R23–R25 did **not** complete D1). **R26:** repaired R25 residuals but Root QA residual NO-GO on STATE matrix holes. **R27:** re-extracts TRANSACTION_STATE reachable public snapshot matrix from **docs/12 + docs/13 Normative reducers** (not incremental patches; 矛盾0 with docs/12/13): SATISFIED={64}; EXPIRED={65,66,20}; UNKNOWN={69,20} (129 AWAITING-only); CANCELLED={82}; FAILED={22,70,80,128}; AWAITING={0,68,83,86,128,129}; WAITING={11,85,128,130,132}; **28** legal positives (DS 23 + EF 5); REQUIRED_EVIDENCE_LATE(65) is EXPIRED not SATISFIED; CANCEL_AFTER_EFFECT(83) AWAITING-only; Mode27 EventFact lifecycle permanent enumeration **4 state-class × 4 spool = 16** (receipt+DISCARDED / discard+RELEASED / nonterminal+DISCARDED etc. RED); EventFact terminal Receipt SATISFIED+64 or audited discard FAILED+80 only; D3-S1 prerequisite boundary explicit. CLI generate/check fail-closed (bool/float/NaN/Infinity/overflow/nested/wrong-first144 exit2) and COMMIT_UNKNOWN five fence paths + non-CU controls **preserved without weakening R16–R26**. Permanent boundary **4380**; secondary differential **typed 74/60**, **body_decode 306/0/306**, **body_roundtrip 132**. Production typed diagnostic is **cross-check only**. Production C is **not** oracle authority. **Production / bridge follow the oracle gate (R28 r3 two-lane bridge 139 green).** Current candidate is **283 = prefix 144 + suffix 139 (production 138 + formal 1)**, content SHA `0155b6929c2bb64396623cd75be283947b76c68d9f5d9578825ae5966b375639` (raw file SHA `8b17304f7edda04495aafa2e8f3a54bd7e57d5c147b8e62fca8a1b6b360740ed`; **vector body +3 EF reason-closure CORRUPT vs R27-Sol; EF AWAITING closed to {0}; Mode27 EF reason closure in oracle classifier + production adoption guard** — R28 is oracle/spec repair + production/bridge追従). This ADR is **Accepted (2026-07-21)** — Sol xhigh r3 P0=0/P1=0; production/bridge evidence green（D3-S4以降 / D3 complete / Stage 5 は本ADRの範囲外）。
- Remaining open（本ADR範囲外の後続）: D3-S4..S12、Stage 5 D3 bind、D4、public Runtime。
- Pre-acceptance GET=0 BIND draft SHA is **withdrawn**; do not pin Accepted on it.
- 本 ADR は **Proposed**（R27-Sol oracle candidate あり; R21–R26 Sol high / Root residual NO-GO; production/bridge/Sol 再審査未完; Accepted ではない; GO 禁止）。

## Rejected alternatives

- u32 fragments in `focus_id16` for Mode28 totals  
- open-ended fault status sets / multi-fault arrays  
- B5 on non-BASELINE walks  
- prose transition exits（“see rows”, “as applicable”, “FOCUS path”, “W+”）  
- private build as REP1-L2 evidence  
- mapping table as equality substitute  
- multiset-stable duplicate key wording  
- Accepted/production-complete claims in this oracle-candidate round  
- **BIND pure-W with GET=0 + offline `idx` omniscience** as REP1-L2（non-constructible under 754 / no full-ID set）  
- **Repeated outer W → per-item G only** as the sole packing（constructible but heavier formal schedule; WG preferred for practical cost）  
- Weakening §18.14.9 reverse/orphan L1 to fit GET=0 BIND walks  
- Mode30 RR multi-count / unbounded bound-man set  
- S3 INTERNAL re-increment of public `ok_row_count` / `current_domain_key_count`  
- Optional reopen prefix that omits either close or open when NEED_REOPEN=1  
- **SELECT W with mid-walk setup `exact_get`**（iter_next→GET→iter_next same drive）  
- Reclassifying SELECT as **WG** to paper over setup GETs（WG remains BIND-only）  

## Acceptance boundary

**Proposed** のまま。deterministic oracle / candidate JSON は存在するが、次を意味しない:

- production C / spy / CMake 完了  
- independent review GO  
- candidate JSON SHA の Accepted authority 化 / bridge green / D3·Stage5 complete  
- ADR Accepted  
- use of withdrawn pre-acceptance GET=0 BIND draft SHA as authority  

implementation 受入時（将来）最低条件:

1. §18.14.9 / §18.14.19 と本 ADR の矛盾 0（W/G/**WG**; frontier/latch; INTERNAL freeze; closed matrix; reopen exact）  
2. independent generator が closed schema + control tuples + BIND-WG gets + Mode30 frontier/latch を再生成  
3. **shipped** reference Core が formal vectors で field-for-field equality  
4. REP1-L1-only 経路を docs 上維持  
5. independent review が transcript 一意性 **and BIND constructibility** で P0=0  

## Related

[docs/17 §18.14.19](../17-foundation-domain-store.md) ·
[docs/17 §18.14.9](../17-foundation-domain-store.md) ·
[docs/17 §18.13.5](../17-foundation-domain-store.md) ·
[ADR-0014](0014-r7-t1c-authenticated-hop-fresh-install-owner.md)（書式先例）
