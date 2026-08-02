# 2026-07-29 Production Attachment EDHOC PA-S0 Spec Repair

> 2026-07-30追記: 下記SHAは当時のaudit snapshotである。Accepted ADR-0020との
> protocol-magic衝突を除くため`NAC1/NAS1/NAR1`へ再採番した現行candidateと検証結果は
> [2026-07-30 production-attachment magic namespace repair](2026-07-30-production-attachment-magic-namespace-repair.md)
> を参照する。

## Status

- **PA-S0 remains Proposed / in progress.**
- **Not** Accepted, **not** GO, **not** `SPEC_ACCEPTED`, **not** implementation-complete, **not** production, **not** HIL, **not** release.
- Persistence-oracle P0 repair (this tranche) targets local **P0=0 / P1=0** before Host EDHOC implementation resumes.
- Production implementation / HIL still **not** claimed.

### Chosen durability model (normative)

**`WRITE_SET_OBSERVED_OLD_PROPOSED_NEW`**

- Write-set = exact 15 complete keys (unsigned-byte order).
- Per key: **observed OLD value** (marker absent; 14 non-marker durable rows present for
  same membership/peer) → **proposed NEW value** (canonical N6 codec wire).
- **Not** attachment-scoped namespace (would require Normative selection + bounded GC).
- N6AL/N6HW keys omit `attachment_id`; re-attach **must not** force OLD=0 members and
  **must not** classify valid second-attachment observed OLD as PARTIAL/corrupt.
- N6AL `next_free_or_peer_floor` / N6HW `high_water_key_generation` are **monotonic
  non-decreasing** across 10k attach/reattach/restart.
- `COMMIT_UNKNOWN` classifies value-images: EXACT_OLD / EXACT_NEW / PARTIAL_n /
  EXTRA / THIRD (only OLD/NEW accepted).
- Non-marker `value_hex` = real N6TX/N6RX 68B, N6AL 56B, N6HW 28B (+ CRC/magic);
  label `NINLIL-PA-N6-CODEC-V1`. Synthetic `NINLIL-PA-N6-VALUE-V1` is permanent
  negative only (must not feed runtime storage/KAT).

### Stable vector SHA (this tranche)

```
4d9a3d62823c09861d88b3cac3e5a795aad97cdaebdedc75c512d3672c537401
```

Prior SHAs (`98a90295…`, `766a5e78…`, …) are historical. Current vector pins:
- `exact_old` / `old_member_count=14` / value-image CU
- canonical N6 codec values (`NINLIL-PA-N6-CODEC-V1`)
- **byte-exact** `carrier_transcript_digest` (docs/35 §4.1; not
  `SHA-256("carrier-transcript")`)

## Context

Independent Sol re-audit of PA-S0 returned **P0=0 / P1=4 / P2=1 NO-GO** while ordinary tests still green. This note records the Proposed repair that closes those findings without promoting status.

## Findings closed (this tranche)

| ID | Class | Finding | Repair |
|---|---|---|---|
| P1-1 | C oracle | C used fixture digests as both expected and observed (self-compare) | C independently recomputes canonical N6 codec wire + context digests; fixture digests checked against recompute; permanent VALUE-V1 filler ≠ codec negative |
| P0-A | CU model | CU fixed OLD=0 members, but re-attach cannot have empty OLD (N6AL/N6HW omit attachment_id) | Write-set Observed-OLD/Proposed-NEW; EXACT_OLD=14 non-marker + marker absent; never classify valid re-attach OLD as PARTIAL |
| P0-B | value authority | non-marker value_hex was synthetic VALUE-V1 filler | Canonical N6 codec rows (TX/RX/AL/HW/N6AT) + permanent VALUE-V1 negatives in Py/Node/C |
| P1-2 | RFC KAT | RFC message digest only vs fixture twin | C-source literal exact bytes + SHA-256 + semantic method/suite pins for RFC 9529 §3 message_1; 03→04 coherent drift rejected by generator self-test, Python, Node, and C |
| P1-3 | Schema | JSON not recursively closed; later Node vector-shape tree was self-authorizing | Hard-coded authority module + independent Py/Node/C pins; vector-derived Node tree **removed**; generator self-checks emission against same envelope authority |
| P1-4 | Strict JSON / types | Node missed decoded-unicode duplicate keys / loose numbers; Python bool-as-int holes | Node strict parser: unicode-decoded key dedup, no `+`/`-0`/leading zero/unsafe/nonfinite; Python `exact_int`/`exact_bool`; parity self-tests |
| P2 | (prior) | C image authority incomplete | Retained: per-member digests + executable same-key value/context substitution negatives for both roles × pending/active |
| follow-on | Authority envelope | Missing schema_version/title/ADR/tools/nonclaims/status_map/lifecycle constants | Envelope hard-coded in schema authority; emitted by generator; enforced by Py/Node/C; coherent all-metadata drift permanent self-test |

## Baseline counterexamples retained

Prior permanent self-tests remain (do not drop):

- `present_keys_concat_sha256` change
- `exact_old.commit_unknown_accepted=false`
- `active_marker_only.value_sha256` deletion
- `accepted_snapshots` + `partial_1`
- value-substitution classification / CU flag change with divergent image
- duplicate JSON key / non-integer number

New permanent self-tests:

- unknown top-level key
- unknown nested key
- `carrier_class=true` (bool-as-int)
- RFC message_1 03→04 coherent
- Node unicode-duplicate key (`schema` / `\u0073chema`)
- Node leading `+` integer and `-0`
- Generator VALUE-V1 filler ≠ N6 codec value
- C VALUE-V1 filler ≠ codec + OLD≠NEW for AL/HW monotonic floors
- Coherent all-metadata drift
- `schema_version` drift / tools path drift / `value_label` X1 / `status_map.accepted=true`

## Schema independence (follow-on)

- Removed Node `PA_CLOSED_SCHEMA_TREE` (vector-shape dump).
- Added `tools/production_attachment_edhoc_schema_authority.py` as hard-coded envelope + case-list authority.
- Generator `canonical_json` refuses to emit without envelope/schema authority pass.
- Python/Node/C each pin the same envelope independently (C via hard-coded string literals vs fixture emission).

## Nonclaims

- No production attachment runtime, EDHOC library, or public ABI claim.
- No Wi-Fi / radio HIL, no release SBOM/status change, no Accepted promotion.
- C fixture remains **TEST_ORACLE_ONLY** data; validation is host C11 gate only.
- Vector `status` remains `PROPOSED_SPEC_ONLY`.

## Verification commands (local)

```text
python3 -m py_compile tools/production_attachment_edhoc_vector_gen.py tools/production_attachment_edhoc_gate.py
python3 tools/production_attachment_edhoc_vector_gen.py --check
python3 tools/production_attachment_edhoc_vector_gen.py --self-test
python3 tools/production_attachment_edhoc_gate.py --check
python3 tools/production_attachment_edhoc_gate.py --self-test
node --check tools/production_attachment_edhoc_gate.mjs
node tools/production_attachment_edhoc_gate.mjs --check
node tools/production_attachment_edhoc_gate.mjs --self-test
# C normal + ASan/UBSan focused binary
# tests-OFF standalone cc of tests/radio/production_attachment_edhoc_vector_test.c
# fresh CTest full suite in dedicated build dir
git diff --check -- <edited files>
```

## Wire-leaf scalar authority (2026-07-29 follow-on P1)

Independent type-preserving scalar-leaf campaign against prior gate snapshots
(`Py=c3cbff47…`, `Node=7b441a32…`) reported 32 both-gate false-greens + 21 Node-only
(artifact `/tmp/audit_pa_wire_leaves_result.json` SHA `f5cdb8a9…`).

### Closed machine surfaces (except free prose)

| Surface | Binding |
|---|---|
| NPR fragment JSON `index` (cookie×2 + install×5) | array position ≡ JSON index ≡ NPR byte[42] |
| install `*_length` / opaque lengths (7) | len(hex) ≡ u16 length field ≡ limits ≡ protected payload size |
| `install_fields` digests/ids/gens | full NAI1 wire map (incl. lease_clock, carrier_transcript, proposal_digest, e2e_security_id, credential generations, route/membership digests) |
| `proposal_fields` e2e/id/stable | full NAP1 wire map |
| N6 marker `key_length`/`value_length`/`local_role`/`state`/`state_name` | decoded key/value + limits + enum↔name |
| Node `limits` (20) + `control_aead.name` | exact pin parity with Python |
| inventory marker identity/layer/value_sha | exact marker metadata + pending value binding |
| `classification_domain` | closed exact list |
| group_machine top role hex/concat | bind to `lifecycle.roles` + NAB concat |
| CU `third_value_hex` | bind to device fenced_third |
| snap15 `marker_state`/`marker_value_hex` | pending state/value |
| substitution members (Node) | full canonical derive + members_equal_exact (Py parity) |

Free (allowed drift): `$.rfc9529_method3_suite2_reference.reason`, `$.credentials.note`.

### Permanent self-tests added

Wire-leaf CE mutations for index/length/opaque/install_fields/proposal_fields/N6 marker/
limits/control_aead.name + role-surface state/name/sha drifts (Py + Node).

### Post-repair campaign self-report

- Full recursive type-preserving walk: **4184** mutatable scalar leaves.
- **Python machine false-greens: 0** (only the 2 free prose leaves accept).
- **Node machine false-greens: 0** (only the 2 free prose leaves accept).
- Post artifact `/tmp/audit_pa_wire_leaves_result_post.json` SHA `e101f363…`.
- Vector SHA `2463ec72…`; gate Py `da808502…`; gate Node `d9d9f6f8…` (pre-identity-hardening SHAs; recompute after identity tranche).
- Remain **Proposed** (no SPEC_ACCEPTED / GO claim).

## Lifecycle+manifest all-leaves campaign (2026-07-29)

Baseline independent campaign against gate `c3cbff47…`:
`/tmp/audit_pa_lifecycle_all_leaves_result.json` SHA `dfa79dc3…` —
**3787** lifecycle+manifest scalars, **588 false-greens** (plus 36 unexpected KeyError on
`rejected_snapshot_kinds` string drift).

Critical surfaces closed (not schema-only):

| Surface | Binding |
|---|---|
| `commit_unknown.third_value_hex` | exact device `fenced_third` bytes (magic destruction rejects) |
| group_machine role key/value/concat ×9 | bind to `lifecycle.roles` + NAB concat SHA |
| `classification_domain` ×25 | exact closed list |
| exact_new `marker_state`/`marker_value_hex` | pending state=1 + pending value |
| NEW/substitution member metadata | index/identity/kind/lengths/value_sha vs inventory + independent identity label function |
| manifest marker inventory | identity=`attachment_marker`, layer=0, value_sha, pending value |
| inventory identity | independent `expected_inventory_identity(kind,dir,lane,layer)` (not free text) |
| role surface / pending_marker / p2a shas | decoded bytes + enum↔name |
| partial/substitution/CU | retained prior hardening |

Post-repair evidence: `/tmp/audit_pa_lifecycle_all_leaves_result_post.json` SHA `95c50979…`

| Metric | Baseline (`c3cbff47…`) | Post-repair |
|---|---|---|
| Scoped leaves | 3787 | 3789 |
| Machine false-greens | 588 | **0** (Py+Node) |
| 588-path replay accepts | n/a | **0** / **0** |
| Descriptive free in scope | n/a | none (reason/note are outside lifecycle+manifest) |
| Vector | (snapshot) | `2463ec72…` |
| Gate Py / Node | `c3cbff47…` / — | `df173637…` / `9d3bd931…` |

Still **Proposed** — this closes the lifecycle scalar false-green set; not GO / SPEC_ACCEPTED.

## Canonical expected-model architecture (design pivot)

Stop ad-hoc per-leaf `if` repair. Machine authority is now:

1. **Independent rebuild** from spec constants / exact layouts / preimage formulas
   (`tools/production_attachment_edhoc_expected_model.py` → pure construction oracle).
2. **Full closed-tree exact equality** (field-by-field + masked canonical serialization)
   of the on-disk vector against that rebuild.
3. **Descriptive allowlist only**:
   - `$.rfc9529_method3_suite2_reference.reason`
   - `$.credentials.note`
4. **Generator vs validator**: emission CLI writes the vector; gates recompute and
   compare (never treat the file as self-authorizing expected content).
5. **Automatic proof**: self-test leaf mutation campaign over all scalar leaves
   (type-preserving) requires 0 machine false-greens; unknown-key 444-path probe
   remains for closed schema.

| Component | Role |
|---|---|
| `expected_model.py` | rebuild + diff + campaign API |
| `gate.py` / `gate.mjs` | equality primary; Node loads expected via `--dump-json` |
| C11 test | independent wire/layout oracle on fixture spans |
| leaf campaign | `leaf_campaign_tested=4184`, `false_greens=0` (Py+Node self-test) |

Evidence command:

```text
python3 tools/production_attachment_edhoc_expected_model.py --check-vector spec/vectors/production-attachment-edhoc-v1.json
python3 tools/production_attachment_edhoc_gate.py --self-test   # includes leaf campaign
node tools/production_attachment_edhoc_gate.mjs --self-test
```

## Node CU list parity (rejected empty / accepted duplicate)

Independent re-audit residual P1: Node accepted (both roles)

1. `commit_unknown.rejected_snapshot_kinds = []`
2. `accepted_classifications` append duplicate `EXACT_OLD`

Root cause: Set-only / incomplete list checks false-green on those drifts. Fix:

- Node `CU_ACCEPTED_CLASSIFICATIONS_EXACT` + `CU_REJECTED_SNAPSHOT_KINDS_EXACT`
- `assertExactUniqueStringList` (ordered equality + uniqueness) for role CU and top-level CU
- Permanent self-tests: both roles × both mutants (Py+Node)

Post evidence `/tmp/audit_pa_cu_list_parity_post.json` — **4/4 reject, parity_defect_count=0**.

## Independent re-audit

Required before any GO / P0=0 claim. This work log is **not** an acceptance certificate.
