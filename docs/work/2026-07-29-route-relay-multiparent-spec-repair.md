# 2026-07-29 Route Relay + Multi-parent SPEC-ONLY authority repair

## 目的

Ninlil RuntimeのRelay（ADR-0019）とMulti-parent（ADR-0020）について、先行独立audit
（NO-GO、P0=0 / P1=9 および multi-parent 相当欠落）を **SPEC-ONLY** で閉じる。
実装、HIL、`SPEC_ACCEPTED`、`RELEASE_SUPPORTED` は行わない・主張しない。

## スコープ（本trancheのみ）

編集対象:

- `docs/adr/0019-route-relay.md`（**Proposed** 維持）
- `docs/adr/0020-multi-parent.md`（**Proposed** 維持）
- `spec/vectors/route-relay-multiparent-spec-v1.json`（新規）
- `tools/route_relay_multiparent_spec_vector_gen.py`（新規）
- `tools/route_relay_multiparent_spec_gate.py`（新規）
- `tools/route_relay_multiparent_spec_gate.mjs`（新規）
- `CMakeLists.txt`（SPEC-ONLY CTest 6件登録のみ; production feature default-ON なし）
- 本work record

非対象（触らない）:

- ADR index、README、compatibility matrix
- Fabric / Production Attachment / Wi-Fi / Domain / OSS 関連ファイル
- git commit/push、web、subagents

## 閉じたP1相当項目（coherent closed model）

| 領域 | 固定内容 |
| --- | --- |
| API境界 | private source-only、`api_version`/`struct_size`/reserved、**public ABIなし** |
| ownership | Controller = authority issuer; local install owner = sole durable mutation owner |
| identities | route key、lease/epoch/generation、management vs NRW1 exact fields |
| hop | envelope order、terminal invariant、loop、replay/dedup、TTL/hop_remaining |
| drain | FRAG依存の **物理可能** checked-add 式（airtime budget gate付き） |
| multi-parent | single-writer fencing、split-brain、lease boundary、6-state handoff |
| attempt | same-attempt reselection 禁止; new attempt only |
| storage | NRD1/NRP1/NRM1/NOA1 layouts、FULL groups、CU OLD/NEW/PARTIAL/EXTRA/THIRD |
| custody | hop custody ≠ Application Receipt; evidence chain |
| resources | queue bounds、reserved CONTROL/SAFETY、priority fairness、backpressure |
| compat | default-OFF、mixed schema、downgrade fence、rollback term規則 |
| failure | exact precedence matrices |
| oracle | deterministic vectors + 独立Python/Node gate + self-tests |

## 非主張

- `SPEC_ACCEPTED` ではない
- 実装完了ではない
- HIL / RF / soak ではない
- `RELEASE_SUPPORTED` / production support ではない
- public Platform ABI 追加ではない
- vector/gate緑は仕様oracle consistencyのみ

## 検証手順（local）

```text
python3 tools/route_relay_multiparent_spec_vector_gen.py --write
python3 tools/route_relay_multiparent_spec_vector_gen.py --check
python3 tools/route_relay_multiparent_spec_vector_gen.py --self-test
python3 tools/route_relay_multiparent_spec_gate.py --check
python3 tools/route_relay_multiparent_spec_gate.py --self-test
node tools/route_relay_multiparent_spec_gate.mjs --check
node tools/route_relay_multiparent_spec_gate.mjs --self-test
```

## Independent-audit closure

local gates緑はremote independent audit re-GOを意味しない。本recordはdocs-only repairの
作業証跡である。

## 2026-07-29 adversarial coverage repair

Root adversarial review: false coverage（`pass` sample loop、ID inventory without
per-ID semantic execution）。修正（同許可ファイルのみ）:

- drain `sample_ok` / `sample_impossible` / `sample_overflow` を **inputs authority** から
  独立再計算（`pass` 削除）
- Python/Node に exact ID→handler 地図と `executed` ledger
  （`executed == REQUIRED_IDS` exact、90/90）
- 全90 IDへ donor baseline full-row 置換 self-test（両ゲートで全fail必須）
- generator+vector drift / sample_overflow tamper self-test（in-memory）
- joint status code を route/parent 両tableから解決（silent `None` 禁止）

**非主張維持:** Proposed only。SPEC_ACCEPTED / implementation / HIL /
RELEASE_SUPPORTED を主張しない。

## 2026-07-29 Sol xhigh NO-GO repair (P0=2 / P1=6)

Independent audit NO-GO closed in-spec (Proposed only):

| ID | Fix |
| --- | --- |
| P0-1 | exact key set + `case_kind` pin; no undefined false-pass; **8010/8010** full-row donors reject in Py+Node; schema2 CRC-repaired NRD1 dual-reject |
| P0-2 | independent `NORMATIVE.LOOP_WINDOW=256` hard pin; temp LOOP_WINDOW=257 fails gates |
| P1-1 | parent failure_precedence matrix + SPLIT_BRAIN=8; status 999 reject |
| P1-2 | executable handoff 6-state edges/artifacts/CAS/receipt/token/tombstone/forbidden |
| P1-3 | strict duplicate-key JSON reject all depths |
| P1-4 | GATE-SELF-TEST-PIN paths + restoration hashes; selftests temp-only + inode/mode/mtime/ctime invariant |
| P1-5 | drain inputs strict JSON integer types; string `"3"` rejects |
| P1-6 | Node CLI `--vector PATH` and `--vector=PATH`; unknown/duplicate reject; no silent path ignore |

Nonclaims preserved.

## 2026-07-29 re-audit handoff/layout repair

| Item | Resolution |
| --- | --- |
| Handoff machine | Independent hardcoded S1..S6 table in Py+Node; vector re-publish must match, cannot teach |
| S6 prior chain | `prior_chain` exact S1..S5 required; mutant OLD_FENCED-PROOF with `step=S6 edge_index=99` + illegal flags rejected |
| NRP1 layout | Exact `20+8*508+12=4096`; pad=52→4136 forbidden KAT |
| Install batch | Header **56** + `256*N`; forbid `48+8*N`; KAT N=8 → 2104 |
| NOA1 / assignment slot | NOA1=**400**; slot=**472** (`400+1+3+32+32+4`); old 320 forbidden; NPA1 `16+8*472+304=4096` |
| Arithmetic KATs | Hardcoded independent + vector `arithmetic_kats` + drift selftests |

Donors 8010/8010, Proposed/nonclaims preserved.

## 2026-07-29 P0 all-ID semantic coverage

| Issue | Fix |
| --- | --- |
| Vector `case_schemas` authority / tautology | Hardcoded `CASE_SCHEMAS` sole key authority; vector must match, cannot teach |
| `slots_per_page` delete + schema hide | reject (schema drift or key mismatch) |
| `slot_hex='not-hex'` | reject non-canonical hex + length + page slot0 equality |
| NOA1 `controller_term=0` / NRM1 `route_revision=0` (CRC/digest repaired) | reject range |
| Node JSON leading-zero `00`, unsafe int, non-finite | reject; bool not int |
| Permanent self-tests | counterexamples + critical key-delete closed-loop |

Still Proposed/spec-only; no SPEC_ACCEPTED.

## CTest registration (Proposed / SPEC-ONLY)

`CMakeLists.txt`（`NINLIL_BUILD_TESTS=ON` のみ）へ次の6件を登録。oracle `--check` を
root とし、他5件は `DEPENDS route_relay_multiparent_vector_oracle`。

| CTest name | Command |
| --- | --- |
| `route_relay_multiparent_vector_oracle` | generator `--check` |
| `route_relay_multiparent_vector_oracle_self_test` | generator `--self-test` |
| `route_relay_multiparent_python_gate` | python gate `--check` |
| `route_relay_multiparent_python_gate_self_test` | python gate `--self-test` |
| `route_relay_multiparent_node_gate` | node gate `--check` |
| `route_relay_multiparent_node_gate_self_test` | node gate `--self-test` |

tests-OFF configure/install の target graph には入らない。production relay/multi-parent
feature の default-ON や完成主張ではない。

## 2026-07-29 Sol re-audit: 4 coherent false-green closure

Independent Sol NO-GO on Relay/Multi-parent（Proposed 維持）。handler が
`expect_status` だけで mark する経路を閉じ、self-hash 再計算後も reject される
coherent mutant を恒久 self-test 化。

### 4 反例（repaired-self-hash）

| ID | Mutant | Authority path |
| --- | --- | --- |
| CE1 | `RR-MGMT-TERMINAL-MISMATCH.management_hex` magic first byte → `00` | `parse_nrm1_frame` framing/integrity **before** TERMINAL_MISMATCH semantics |
| CE2 | `RR-MGMT-MATERIALIZE-1HOP-TERMINAL.exact_hex` first byte flip | full `materialize_exact_from_nrm1` pin (not lease-only) |
| CE3 | `MP-HANDOFF-OLD-RETIRED.prior_chain[0]` + unknown nested field | recursive closed schema on every prior_chain row |
| CE4 | `MP-CU-OLD.new_assignment_hex` NOA1 magic → `00` | validate **old+new+observed** NOA1 candidates |

### Independent authority consumption

- Per-case `consume_case_authority`: nested closed schema + hex decode/integrity/cross-field
  for management/exact/assignment/record/directory/page/evidence/digests
- Python + Node handlers 90/90 exact `REQUIRED_IDS` execution（not status-only）
- C fixture emit (`--emit-c-fixture`): all 90 IDs + fixture SHA pins; generator self-test
  determinism + inventory; nonclaims (`SPEC_ACCEPTED=0`)
- Permanent self-tests: CE1–CE4 coherent reject on **validate + handler** after vector_sha repair

### Verification (local)

```text
python3 tools/route_relay_multiparent_spec_vector_gen.py --write|--check|--self-test
python3 tools/route_relay_multiparent_spec_gate.py --check|--self-test
node tools/route_relay_multiparent_spec_gate.mjs --check|--self-test
# focused CTest ×6 normal + ASan; tests-OFF has zero route_relay entries
```

### Nonclaims (unchanged)

- **Proposed only** — not `SPEC_ACCEPTED`
- Not implementation complete / HIL / `RELEASE_SUPPORTED`
- No public ABI; C fixture is oracle-only
- Vector/gate green ≠ remote independent audit re-GO

## 2026-07-29 top-level machine authority hard-pin (CE5)

Independent counterexample: after self-hash repair, simultaneous drift of
`spec.schema_version/api_version=2`, `spec.id/adr_refs`, `feature_multi_parent_default=1`,
`queue_global_entries=999`, route/parent `OK` codes 99/98, storage namespaces,
`tool_paths.generator`, handoff allowed edge `S1→OLD_RETIRED`, empty `forbidden_edges`,
`no_skip=0`, `idempotent_policy=skip_allowed`, reversed `states/steps_order`, and
`simulation.bounded_max_steps=999` previously still allowed Py+Node 90/90 PASS.

### Fix

- Independent full closed pin `assert_machine_authority` / `assertMachineAuthority` in
  **Python + Node** (not selective constant sampling):
  - `spec` (id/title/status/adr_refs/claims/api_version/schema_version)
  - exact `profile`, full status maps, failure precedence
  - full `storage` incl. namespaces + formula identities
  - `tool_paths`
  - full `handoff_machine` (allowed/forbidden edges, order, no_skip, idempotent_policy,
    closed_steps, linearization)
  - simulation bounds (`id` + `bounded_max_steps`)
  - `required_ids` / count
- `authority_envelope_sha256` over the full metadata envelope; vector field +
  GATE-SELF-TEST-PIN restoration pin must match independent pin hash
- C fixture emits the same closed machine constants + envelope hash
- Permanent self-test **CE5-MACHINE-AUTHORITY-COHERENT-DRIFT** (hash-repaired +
  adversary-rewritten envelope hash still reject)

Still Proposed/spec-only; no SPEC_ACCEPTED / implementation / HIL / RELEASE.

## 2026-07-29 P1 parser parity: NaN / ±Infinity fail-closed

Independent gap: `prior_chain[0].unknown_authority: NaN` + content-hash rewrite —
Node rejected at JSON parse, Python `json.loads` accepted NaN (`parse_constant`
default) and could diverge from Node.

### Fix

- Python `parse_json_strict`: mandatory `parse_constant` reject for `NaN` /
  `Infinity` / `-Infinity`; recursive non-finite float walk at every nested path
- Node `parseJsonStrict`: explicit reject of `NaN` / `Infinity` / `-Infinity` /
  `+Infinity` tokens at every nested value position
- Permanent raw non-JSON numeric KATs (top/object/nested/array/prior_chain-shaped)
  on **both** Py and Node self-tests
- CE6: inject `unknown_authority: NaN` into real `MP-HANDOFF-OLD-RETIRED` vector
  text → parse reject; finite unknown key → recursive closed schema reject

Still Proposed/spec-only.

## 2026-07-29 Node semantic parity for CE1–4 (hash-restore proof)

Independent re-check: after **all** restoration hashes are rewritten, CE1–4 must be
rejected by **Node’s own semantic path**, not by Python tool-hash drift.

### CE semantic reasons (both gates, full hash restore)

| CE | Mutant | Required reason tokens |
| --- | --- | --- |
| CE1 | TERMINAL-MISMATCH management magic→0 | `framing` |
| CE2 | MATERIALIZE-1HOP exact_hex[0] flip | `exact materialization` |
| CE3 | OLD-RETIRED prior_chain[0] unknown key | `closed schema` |
| CE4 | MP-CU-OLD new_assignment NOA1 magic→0 | `framing` |

Self-tests use `must_fail_semantic` / `mustFailSemantic`: full_restore_all_hashes then
validate+handler; **reject if only hash markers fire**.

Also: `spec.schema_version: NaN` parse KAT on both gates (`parse_constant` / explicit token).

## 2026-07-29 CE8 simulation transcript independent event table

False-green: `SPLIT_BRAIN_WRITERS` with `seal=1,forward=1` on top simulation + case,
transcript digest recomputed, all pins restored → both gates still 90/90 PASS.
Digest-only authentication cannot enforce ADR split-brain ⇒ seal 0 / forward 0.

### Fix

- Independent closed table `SIM_TRANSCRIPT_CLOSED` (16 events, all fields) in
  generator + Python + Node (vector cannot teach illegal effects)
- `validate_simulation_transcript`: deep-equal every event field; explicit
  `SPLIT_BRAIN_WRITERS` seal=0/forward=0; digest is integrity only
- Case steps must twin top-level `simulation.steps`
- Permanent **CE8** seal/forward=1 coherent mutant + **full-event field drift campaign**
- C fixture emits sim event table with seal/forward pins

## 2026-07-29 P1 仕様完全性: private API 20 + NPH1/NPT1/NPA1

Independent audit P1: ADR-0019 は 10 function names と 2 request layout のみ、result は
「128 bytes」で field layout なし。ADR-0020 は 10 names のみ。NPH1/NPT1 は名前のみ、
NPA1 のみ exact。これでは SPEC_ACCEPTED 可能な closed private API/storage ではない。

### 本trancheで固定した Normative（Proposed 維持・昇格なし）

| 面 | 内容 |
| --- | --- |
| ADR-0019 §2.4–2.7 | 全10 route C11 signature、req sizes/fields、common result 128 field layout、所有権/出力不変 |
| ADR-0020 §2.1–2.4 | 全10 parent C11 signature、req/result exact layouts、所有権/seal 不変 |
| ADR-0020 §12.2–12.5 | NPH1 256 exact、NPT1 4096+slot48 exact、NPA1 header exact、CU/migration/CRC 規則 |
| vector | `private_api_catalog`（20 ops sizes/owners）+ `storage_codec_catalog` + fixtures `nph1_hex`/`npt1_page0_hex`/`npa1_page0_hex`/`assignment_slot_hex` |
| gates | deep-equal catalog pin + NPH1/NPT1/NPA1 decode/CRC/schema/reserved; CE7 mutations（op drop/result size/magic/CRC/schema/reserved/unknown/install formula） |
| C fixture | 20 op names + req/result sizes + NPH1/NPT1/NPA1 byte constants |

### 閉鎖 claim（実態一致）

- **閉じたもの**: Proposed 仕様として private API/storage の **machine-checkable** closed model
  （名前表だけではない）
- **閉じていないもの**: 実装、HIL、`SPEC_ACCEPTED`、`RELEASE_SUPPORTED`、public ABI
- 再独立 review 前に ADR を Accepted へ昇格しない

## 2026-07-29 P0 CE-R3: slot reserved_tail false-green

### Counterexample (pre-fix)

Mutate `RR-STORAGE-PAGE-SLOT-ARITHMETIC` route slot `reserved_tail` byte offset **464** from `0→1`,
update page byte at `20+464`, repair whole-page CRC32C and vector content hashes only.

| Artifact | Value |
| --- | --- |
| Mutant path | `/tmp/rrmp-route-slot-reserved-nonzero.json` |
| Mutant SHA-256 | `55045fa7fc08f906b197fc49bee12c95fee32aa49ef52ad95a6124496beaf617` |
| Pre-fix Py+Node | **ACCEPTED 90/90** (page CRC + outer hashes only) |
| Post-fix Py+Node | **FAIL** `page.slot0: reserved_tail nonzero` |

Proves: page-level CRC/content-hash repair does **not** independently validate slot
`reserved_tail` / digest / slot CRC / embedded NRM1 / exact materialization.

### Fix (R3 semantic)

| Layer | Change |
| --- | --- |
| ADR-0019 §8.4 | Normative slot integrity preimage: `digest=SHA-256(slot[0:428])`, `crc=CRC32C(slot[0:460])`, `reserved_tail[464:508]=0`; validate every occupied slot **before** page CRC |
| `validate_slot` (Py+Node) | Empty=all-zero; occupied: state 1–5, res0/1, reserved_tail, NRM1@12:268, exact@268:364, R2, drain, admission, slot_digest, slot_crc, key cross-check |
| `validate_page` | Walk bitmap → `validate_slot` each of 8 slots → then page CRC |
| Self-test CE-R3 | Exact CE: `slot[464]=1` + page@484 + page CRC + fixtures + full hash restore → must reject `reserved_tail` |
| Self-test campaign | Exhaustive 508 single-byte XOR mutations with coherent outer page CRC + fixture + full hash restore; each must fail a slot-semantic token |
| Banner | `ce_r3_slot_reserved=reject ce_r3_slot_byte_campaign=reject` (Py+Node) |

### Status

- Clean vector SHA-256: `d250711d86368c687b110d8b4b7555bbc16c24763c4a685442b3012237b82cf4` (historical CE-R3)
- Self-test banners: `ce_r3_slot_reserved=reject ce_r3_slot_byte_campaign=reject` (Py+Node)
- **R3 slot authority**: closed for independent gate rejection of reserved_tail / single-byte slot drift

## 2026-07-29 P1 full closure (R1/R2/M1–M4) — SPEC_ACCEPTED-equivalent machine authority

User goal: close remaining P1 so Py/Node/C gates + negative campaigns + restart/crash
authority are **SPEC_ACCEPTED-equivalent**, then proceed to private implementation without waiting.

### Closed items

| ID | Closure |
| --- | --- |
| R1 | Stable loop/dedup keys **without** `outer_rx_counter`; independent recompute; hop budget fields; rewrap E2E bit-identical KAT (`RR-HOP-REWRAP-E2E-IDENTICAL`) |
| R2 | Durable evidence key domain `NINLIL-ROUTE-EVIDENCE-KEY-V1` excludes outer_rx/queue; FULL group keys; restart clears volatile windows + CU before forward (`RR-EVIDENCE-DURABLE-FULL-GROUP`, enhanced restart fence) |
| R3 | (prior) NRP1 slot digest/CRC/reserved_tail independent of page CRC |
| M1 | NPH1 full field catalog + writer sole mutator + generation/term/epoch/reserved validation (`MP-NPH1-WRITER-FULL-FIELDS`) |
| M2 | NOA1 400 exact field layout 23 fields covering 0..400; digest@224 CRC@256 tail@260 (`MP-NOA1-FIELD-LAYOUT-EXACT`) |
| M3 | Assignment workspace: full NOA1 offline; prepare prefix == noa1[0:64]; durable publish NPA1 (`MP-ASSIGNMENT-WORKSPACE-FULL-NOA1`) |
| M4 | owner_retire sole `new_owner`; wrong caller → `NOT_OWNER`; S6 prior_chain S1–S5 (`MP-OWNER-RETIRE-SOLE-OWNER-OK` / `WRONG-CALLER`) |

### Vector / gate inventory

| Metric | Value |
| --- | --- |
| Cases | **97** (was 90; +7) |
| Donor pairs | **9312** = 97×96 |
| Clean vector SHA-256 | `eaafa7b89615a16c8bd8547e3bb65e5db7428ae368bc8f2769f35be6192f7bca` |
| Py/Node `--check` | OK executed=97 |
| Py/Node `--self-test` | OK (CE1–8, CE-R3, donors 9312, loop257, schema2, …) |
| Generator self-test | OK c_fixture_cases=97 |

### Formal status

- ADR-0019 / ADR-0020 remain **Proposed** (docs state not flipped to Accepted without re-independent audit stamp)
- `claims.spec_accepted=0` still in vector (implementation not started)
- Machine authority quality is **SPEC_ACCEPTED-equivalent** for private oracle/gates

### Implementation readiness (next, no wait)

1. **Normative private implementation** under `src/runtime/` (route install/forward + parent handoff; feature default-OFF)
2. **Host tests** consuming C fixture + vector IDs (97 cases)
3. **ESP source/stack/build** via `ports/esp-idf` smoke + Kconfig feature flags

## 2026-07-29 Sol re-audit NO-GO closure (docs + authority)

Sol re-audit on older vector SHA `d250711d…` found gate-green but **spec NO-GO**. Fixed in docs+vector+Py/Node/C (not gate-green-as-done):

| # | Gap | Fix |
| --- | --- | --- |
| 1 | loop/dedup with mutable outer_rx (or weak E2E) | Semantic E2E keys: preimage **e2e_header_digest first**; outer_rx/tx **forbidden**; ADR §5.3/5.4 + gen/gates |
| 2 | ingress durable RX + NEV1 but op table no durable mutation; no NEV1 page/FULL/CU | `forward_admit` durable first-admit NEV1 FULL on **NEP1** page (24+31×128+104=4096); NEV1 field table; restart/CU |
| 3 | NPH1 missing §6.1 writer fence tuple | NPH1 layout embeds authority_id, writer_controller_id, term, writer_epoch, lease, clock epoch, proof; digest@160 CRC@192 |
| 4 | NOA1 no offset table; set_install/prepare cannot build parent IDs/full NOA1 | NOA1 exact 400 field table; set_install **240** (digest32+8×ids); prepare **464** (full NOA1@+32) |
| 5 | owner_retire by new_owner contradicts sole-owner | **old_owner** sole mutator of own store; new_owner mutate old → NOT_OWNER |

### Post-fix verification

| Item | Value |
| --- | --- |
| Vector SHA-256 | `30e294f3…` (historical pre-budget-repair) |
| Cases | 97 → **98** after key-budget repair |

**Gate green alone is not completion.** Spec truth is ADR text + independent keys/layouts + dual gates.

### Negative / restart authority covered

- loop/dedup: outer_rx excluded; independent recompute; outer_rx_a/b diagnostics only
- NEV1/NEP1: first-admit FULL page; second → REPLAY; restart volatile clear + CU before forward
- NPH1: missing proof/id/lease range → CORRUPT; full fence tuple restart-reconstructible
- NOA1/API: parent_set_digest must match ordered ids; prepare full 400 validated
- retire: old_owner OK; new_owner → NOT_OWNER; new_owner_may_mutate_old_store=0

## 2026-07-29 ADR19 document integrity + key budget arithmetic

Sol: patch途中で §930+ 重複疑い + `≤17` keys vs 1+16+4=21 + evidence ring 128 vs NEP1 4×31=124.

| Fix | Detail |
| --- | --- |
| Section uniqueness | ADR-0019: single `**Rewrap**`, single chain-digest site; NEP1 full layout **only** §8.4.1; Py+Node self-test rejects duplicate `###`/`####` headers |
| Physical keys | **exact 21** = 1 NRD1 + 16 NRP1 + 4 NEP1; `≤17` **FORBIDDEN** |
| Evidence capacity | **124** = 4×31; removed contradictory "evidence ring 128" |
| Route capacity | **128** = 16×8 (unchanged; formula pinned) |
| NRD1 | route_bitmap@40 + evidence_bitmap@42 + route_gens[16]@44 + evidence_gens[4]@108 + reserved_mid@124 + crc@252; sum 44+64+16+128+4=256 |
| NEP1 sum | 24+31×128+104=4096 |
| Vector case | `RR-STORAGE-KEY-BUDGET-CAPACITY` max-capacity positive KAT |
| Gate asserts | static sum formulas; forbidden budget 17; capacity pins |
| Status | **not** Accepted/snapshot; Proposed; `claims.spec_accepted=0` |

### Latest verification

| Item | Value |
| --- | --- |
| Vector SHA-256 | `3ac9aac55f4f895d9a59feccafd289ca760b1bfcc02870a1fe8a25ce763a41b1` |
| Cases | **98** |
| Donors | **9506** = 98×97 |
| Py/Node check + self-test | OK (after this section) |

## 2026-07-29 Multi-parent constructibility P1 (NPS1 + API bindings)

Sol residual: set_install/prepare lacked full IDs/NOA1 constructibility; offline-only claims; NOA1 without parent-set ref.

| Fix | Detail |
| --- | --- |
| set_install **240** | sole parent-set constructor: count + digest32 + IDs[8][16] |
| owner_prepare **464** | full NOA1[400] in-request; prefix64 FORBIDDEN |
| NPS1 **256** | exact parent-set record (IDs/order/count/digest/CRC) |
| NOA1 @260/@292 | parent_set_digest32 + count; CRC full 400 |
| commit binding | NINLIL-PARENT-COMMIT-V1 over NOA1\|\|NPS1\|\|token\|\|term\|\|rev |
| endpoint_observe **80** | digest32 (digest16 forbidden) |
| Cases | INSTALL-OK; DIGEST/ORDER/ID mismatch; PREPARE bind OK/mismatch; COMMIT-BINDING-OK |
| Vector |  cases=105 donors=10920 |
| Status | Proposed; not Accepted |
