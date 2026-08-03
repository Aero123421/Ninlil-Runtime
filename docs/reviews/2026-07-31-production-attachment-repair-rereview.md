# Production Attachment PA-S0 repair independent re-review

Date: 2026-07-31  
Reviewer role: independent GPT-5.6 Sol high, read-only  
Decision: **NO-GO — P0=0 / P1=1 / P2=2**  
Promotion performed: none

## Scope and reproduced green evidence

The review inspected the repaired Production Attachment EDHOC PA-S0
specification, generated vector, Python/Node authorities, C11 gate, and global
protocol-magic registry. It independently reproduced:

- focused normal CTest: 10/10 PASS;
- ASan/UBSan C11: 1/1 PASS;
- C11 reported cases: 70;
- Python mutations: 8,324, including 767 unknown-key and 7,458 leaf cases;
- Node mutations: 8,319, including 767 unknown-key and 7,458 leaf cases;
- reported false greens in those existing campaigns: 0.

Those results do not close the findings below because the missing transitions
were outside the exercised state space.

## P1 — pre-auth scratch/token lifecycle is not executed

`build_preauth_owner_model()` checks quotas and a token value, then stores one
owner timestamp. It does not execute the normative two-fragment scratch
lifecycle: fragment 0/1 ownership, exact duplicate, conflicting duplicate
terminal discard, completion, or release.

The `TOKEN_BUCKET_DENY` branch had zero executions under an independent line
trace. Refill is performed only as part of one idle-expiry path. The existing
old-cookie case rejects a fresh request; it does not terminally discard an
already allocated scratch. Python/Node authorities compare five result
strings, and C11 checks constants rather than running the owner transition
system.

Primary evidence:

- `tools/production_attachment_edhoc_composition.py:2798`
- `tools/production_attachment_edhoc_gate.py:2751`
- `tools/production_attachment_edhoc_independent_authority.py:440`
- `tools/production_attachment_edhoc_gate.mjs:2607`
- `tests/radio/production_attachment_edhoc_vector_test.c:4022`
- `docs/35-production-attachment-edhoc-profile.md:368`

Required close: independently executable Python, Node, and C11 bounded owner
models covering both fragments, duplicates/conflicts, completion/release,
token deny and exact refill boundaries, quota boundaries, idle expiry, and
current/previous/expired cookie buckets.

## P2 — global magic registry is not repository-wide or closed

The registry gate validates only the five JSON entries
`NAC1/NAR1/NAS1/NPA1/NPS1`; it does not prove that repository protocol/storage
magic values such as `NLR1`, `N6TX`, `N6RX`, `N6AL`, and `N6HW` are declared.
It also does not close `status` or `artifact` value domains and uses ordinary
`json.loads`, which accepts duplicate object keys.

Independent mutants incorrectly accepted:

- `status="UNKNOWN_PROMOTED"`;
- `artifact=false`;
- a duplicate `status` key in one entry.

Primary evidence:

- `tools/protocol_magic_registry_gate.py:28`
- `spec/protocol-magic-registry-v1.json:11`
- `tools/domain_scan_vector_gen.py:72`

Required close: duplicate-key rejection, closed schemas/types/value domains,
repository-wide inventory/scan with explicit exclusions, and mutants for an
undeclared repository magic, stale/missing entries, collisions, bad types,
unknown status, and duplicate JSON keys.

## P2 — independent authorities still re-check generated literals

The pre-auth independent authority compares constants and five result strings.
The C11 local-key loop does not inspect each row, and its EAD, downgrade, and
pre-auth checks add acceptance case IDs after constant/count checks. The
expected-model path is still derived from the same composition source.

Primary evidence:

- `tools/production_attachment_edhoc_independent_authority.py:440`
- `tests/radio/production_attachment_edhoc_vector_test.c:3958`
- `tests/radio/production_attachment_edhoc_vector_test.c:4011`
- `tools/production_attachment_edhoc_expected_model.py:349`
- `tools/production_attachment_edhoc_compose.py:14`

Required close: execute row-specific and transition-specific semantics in all
three authorities and add coherent-drift mutants that can distinguish a
generator defect from a fixture edit.

## Prior finding disposition

| Finding | Result |
| --- | --- |
| PA-RV-P1-01 exact OLD/NEW classification | Closed |
| PA-RV-P1-02 prerequisite and local-key constructibility | Closed for PA-S0 |
| PA-RV-P1-03 suite 2/3 M1–M4, EAD, downgrade | Closed for the synthetic-profile scope |
| PA-RV-P1-04 actual NAR owner | Closed |
| PA-RV-P1-05 pre-auth lifecycle | **Open P1** |
| PA-RV-P2-01 global magic registry | **Open P2** |
| PA-RV-P2-02 NAS lifecycle | Closed |
| PA-RV-P2-03 independent-authority drift | **Open P2** |
| PA-RV-P2-04 composable module lane | Remains owned by ADR-0028; not an additional PA-S0 blocker |

Real EDHOC provider/crypto KAT, cross-provider equality, production
NAR/NAS/EDHOC owners, USB/Wi-Fi/SX1262 physical HIL, and field evidence remain
`NOT_RUN` or open. ADR-0023 remains Proposed.
