# Production Attachment PA-S0 fresh closure review

Date: 2026-07-31  
Reviewer role: independent Codex review, implementation changes prohibited  
Reviewed snapshot: branch `codex/runtime-completion`, HEAD `e756aa0`, dirty working tree  
Decision: **NO-GO — P0=0 / P1=0 / P2=3**  
Promotion performed: none  
ADR-0023 state: **Proposed**  
Physical HIL: **NOT_RUN**

## Scope and review method

This review independently inspected:

- `docs/adr/0023-production-attachment-edhoc-profile.md`;
- `docs/35-production-attachment-edhoc-profile.md`;
- `spec/vectors/production-attachment-edhoc-v1.json`;
- the Python, Node.js, and C11 PA-S0 gates and their fixture generation path;
- `spec/protocol-magic-registry-v1.json` and
  `tools/protocol_magic_registry_gate.py`;
- `docs/work/2026-07-31-production-attachment-rereview-no-go-repair.md`.

The prior review verdict and the repair record were treated as claims to
reproduce, not as acceptance evidence. Fresh build directories under `/tmp`
were used so the existing dirty working tree was not modified. This review
file is the only repository file authored by the reviewer.

## Findings

### PA-FCR-P2-01 — The protocol-magic scan can false-green on collisions

**Evidence**

The Normative profile requires every exact four-byte uppercase/digit literal
in the fixed machine-source roots to be classified and requires global
collisions to be rejected
(`docs/35-production-attachment-edhoc-profile.md:40-57`).

The Python gate's candidate pattern only recognizes a complete quoted token:

```text
(?<![A-Za-z0-9_])(?:[bBuU])?["']([A-Z][A-Z0-9]{3})["']
```

(`tools/protocol_magic_registry_gate.py:24-28`). The Node gate repeats the
same pattern. It does not recognize common repository encodings such as:

- `{'N','A','C','1'}`;
- big-endian `0x4e414331u`;
- little-endian `0x3143414eu`.

A direct probe against both gate regexes returned `NAC1` for `"NAC1"` and an
empty candidate list for all three alternate forms. The repository already
contains unclassified uppercase/digit four-byte values in these forms, for
example `NRSV` at `src/runtime/runtime_public.c:19`, `D2S1` at
`src/model/domain_schema1_runtime_binding.h:104`, and `D2T7` at
`src/model/domain_schema1_startup_authority.h:31`. Whether each is a protocol
magic or an in-memory/seal exclusion is exactly the classification decision
the registry is intended to make; the current scanner silently omits it.

The scan also collapses occurrences to a set of token values before comparing
that set with registry entries (`tools/protocol_magic_registry_gate.py:370-398`).
Consequently, adding an existing registered token such as `"NAC1"` as a new
magic in an unrelated component remains “declared” and does not fail. The
14-mutant self-test adds a new undeclared quoted token, but has no alternate-
encoding mutant and no existing-token/different-owner repository mutant
(`tools/protocol_magic_registry_gate.py:548-568`).

**Risk**

The reported `entries=65 / exclusions=97 / candidates=162` is complete only
for the narrow quoted-token regex. It does not prove the documented global
wire/storage collision namespace, so a new collision can pass both Python and
Node authorities.

**Required close**

Extract all supported C/C++/Python/Node/CMake literal representations, or
replace heuristic discovery with an exact occurrence manifest generated from
syntax-aware scanners. Bind every occurrence to an allowed owner/authority
path instead of comparing token sets only. Add rejection mutants for:

1. a four-byte char array;
2. big- and little-endian numeric constants;
3. an existing registered magic reused by an unrelated owner/path;
4. escaped/concatenated forms that the project permits.

Confidence: **high**.

### PA-FCR-P2-02 — The nine local-key failures are names and outcomes, not input-driven transitions

**Evidence**

The profile defines an eight-field local static-DH input and requires distinct
wrong identity/role/curve, public/private mismatch, revision/generation
rollback, unknown reference, reentry, and partial-output failures
(`docs/35-production-attachment-edhoc-profile.md:120-135`).

The vector's nine `prerequisites.failure_matrix` rows contain only an `id` and
postulated output/status counters
(`spec/vectors/production-attachment-edhoc-v1.json:9968-10049`). They contain
no baseline input plus failure-specific input mutation.

The independent Python authority verifies the exact ID list and repeats the
postulated counters (`tools/production_attachment_edhoc_independent_authority.py:355-375`).
The Node authority does the same
(`tools/production_attachment_edhoc_gate.mjs:2490-2515`). The C11 function
matches each ID, unconditionally zeroes a local 32-byte buffer, and checks the
row's recorded counters; it never feeds a wrong identity, wrong role, rollback,
reentry, or partial provider result through a transition function
(`tests/radio/production_attachment_edhoc_vector_test.c:4355-4399`).

Therefore `NINLIL_PA_LOCAL_KEY_FAILURE_COUNT == 9` and the 70-case ledger do
not substantiate the repair record's “row/input” execution claim.

**Risk**

A generator can emit nine correctly named terminal rows while the described
descriptor/provider checks are absent or incorrectly ordered. The three
language gates still pass because they validate expected outputs rather than
derive them from failure-specific inputs.

**Required close**

Materialize a valid baseline descriptor/port invocation and one typed input or
provider-behavior delta per failure ID. Execute a bounded transition model
independently in Python, Node.js, and C11, deriving the terminal state,
zeroization, and zero side effects from those inputs. Add coherent mutants
that alter only each input and prove the corresponding path changes.

Confidence: **high**.

### PA-FCR-P2-03 — EAD_1..EAD_4 stage coverage is not closed by the independent oracle

**Evidence**

The committed vector currently has the correct four rows with stages 1, 2, 3,
and 4 and non-empty `ead_hex` (`spec/vectors/production-attachment-edhoc-v1.json:1216-1252`).
However, the independent Python authority checks the ordered IDs and terminal
counters but does not check `stage` or `ead_hex`
(`tools/production_attachment_edhoc_independent_authority.py:412-427`).

Two in-memory coherent probes were run directly against
`assert_independent_authority_closed`:

```text
ead-empty ACCEPT
ead-stage-duplicate ACCEPT
```

The second probe changed all four rows to `stage=1`; the first emptied all four
EAD inputs. The Node semantic authority requires non-empty `ead_hex` but does
not bind each ID to its stage (`tools/production_attachment_edhoc_gate.mjs:2563-2585`).
The C11 machine accepts any per-row stage in the range 1..4 and does not assert
the ID/stage bijection or uniqueness
(`tests/radio/production_attachment_edhoc_vector_test.c:4402-4443`).

The pinned full-tree SHA rejects a one-off edit today, but it is not an
independent semantic oracle for a coherent generator change plus pin update.
Thus the gates do not independently prove that non-empty EAD at stages 2, 3,
and 4 is exercised.

**Risk**

The `PA-EDHOC-EAD1-EAD4-TERMINAL` acceptance ID can stay green while all four
negative rows exercise only one stage. This is a false-green in a mandatory
fail-closed profile rule.

**Required close**

Make `(id, stage)` an exact bijection for 1..4 in Python, Node.js, and C11;
parse and consume a non-empty EAD input at the selected stage; and add coherent
stage-duplication, stage-swap, and empty-EAD mutants outside pinned-tree
equality.

Confidence: **high**.

## Reproduced green evidence

The following evidence was independently rerun and is valid for what it
actually covers:

- vector SHA-256:
  `11e3e8dcbbd6bdc331c13e0818aa5dadb87f1840c9e46e7d7b961ee816972962`;
- fresh focused normal CTest: **10/10 PASS**;
- fresh ASan/UBSan C11 CTest: **1/1 PASS**;
- strict C11 ledger: **70** executed acceptance IDs;
- Python self-test: **9,346** mutations, **829** object paths,
  **829/829** unknown-key rejection, **8,418** scalar mutations,
  **0** reported false greens;
- Node self-test: **9,341** mutations, **829** object paths,
  **829/829** unknown-key rejection, **8,418** scalar mutations,
  **0** reported false greens;
- magic registry self-test: **65** entries, **97** exclusions,
  **162** quoted-token candidates, **14/14** configured mutants rejected;
- vector generator `--check` and `--self-test`: PASS;
- Python syntax compilation and Node syntax check: PASS.

The pre-auth owner repair is closed for this PA-S0 scope: the independent
Python replay derived **31 transitions**, **17/17 non-zero branches**, exact
fragment lifecycle, quota/refill/idle/current/previous/older-bucket results,
and zero pre-cookie identity/resolver calls. Node and C11 run separate owner
implementations over the same inputs, and C11 includes three input-owned
coherent probes.

Suite 2 and suite 3 Message 1..4 fixtures, mandatory Message 4 timing, and the
no-automatic-downgrade transition also reproduced as specified. The
downgrade row is exact and requires a fresh policy revision and fresh session
generation.

## Status and non-claims

The status boundary is correct and must not be promoted by this review:

- ADR-0023 and chapter 35 remain **Proposed**;
- vector status is `PROPOSED_SPEC_ONLY`;
- `accepted=false`, `spec_accepted=false`, `implementation=false`,
  `hil=false`, and `release=false`;
- real EDHOC/provider crypto KAT, production owners, protected-exchange AEAD,
  physical USB/Wi-Fi/SX1262 HIL, field, and legal evidence remain open.

Physical HIL was not requested or executed in this software closure review and
remains **NOT_RUN**.

## Closure decision

**NO-GO — P0=0 / P1=0 / P2=3.**

The focused normal and sanitizer gates are green, but the protocol-magic
collision authority, local-key failure transitions, and EAD stage-specific
independent oracle are not yet false-green resistant. Software closure requires
all three findings to be repaired and independently re-reviewed while keeping
ADR-0023 Proposed and physical HIL NOT_RUN.
