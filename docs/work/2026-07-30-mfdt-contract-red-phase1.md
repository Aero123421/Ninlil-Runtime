# MFDT repaired contract + executable RED — phase 1

Date: 2026-07-30  
Status: **CONTRACT_FIXED_RED / Proposed SPEC-ONLY**  
Scope: ADR-0021 normative contract, sealed vectors, independent gates, and a
standalone production RED witness. No production GREEN implementation is
claimed or included in this phase.

## Outcome

The contradictory MFDT candidate was replaced with one closed contract before
production repair:

- Accepted control remains exactly `[1, 2]`; selected control `3` is rejected.
- MFN1 is an independent v1 negotiation on `0x34/0x35`.
- The fourteen transfer messages occupy the minimal contiguous candidate range
  `0x36..0x43`.
- The earlier proposed `0x3e/0x3f + 0x40..0x4d` allocation is void history,
  not a second live interpretation.
- NRC1 uses 72 fixed 208-byte slots, 15020 value bytes, and 15056 logical
  bytes. Slot identity is `(session_generation, request_id)`.
- Host ownership is exactly four 65536-byte slots plus a 512-byte coordinator
  (262656 bytes). Fifth admission returns CAPACITY with zero mutation.
- Terminal expiry is canonical NM30 `ABORTED / EXPIRED(5)` with generation 0
  and zero actor. Wire ABORT reasons remain authority reasons 1..4.
- Restart validates full ACTIVE, NRC1, and NM30 semantics before installation.
- Reservation and retention deadlines require checked arithmetic and the same
  trusted clock epoch.
- Reference FULL counts are receiver 77 / sender 67; daily reference totals are
  154 / 134.

Normative sources:

- `docs/adr/0021-multi-frame-durable-custody.md`
- `docs/06-versioning-and-compatibility.md`
- `docs/34-v2-runtime-fabric-completion.md`

## Machine authority and independent gates

The generator emits 93 closed vector IDs. Python and Node independently enforce
closed schemas plus semantic ACTIVE/NRC1/NM30 validation. The C11 authority
pins message allocation, NRC1 dimensions, Host resource bounds, vector/map
seals, and literal wire KATs.

Files:

- `tools/multi_frame_durable_transfer_spec_vector_gen.py`
- `spec/vectors/multi-frame-durable-transfer-spec-v1.json`
- `tools/multi_frame_durable_transfer_spec_gate.py`
- `tools/multi_frame_durable_transfer_spec_gate.mjs`
- `tests/model/multi_frame_durable_transfer_c_authority.h`
- `tests/model/multi_frame_durable_transfer_c_gate_test.c`

The Python and Node gates also reject stale candidate semantics in current
normative/explanatory surfaces. The 2026-07-29 work record is explicitly marked
superseded and its numeric summaries were corrected.

## Executable production RED witness

`tests/runtime/mfdt_v1/mfdt_v1_contract_red_test.c` compiles only against the
current private production headers. `tools/mfdt_v1_contract_red.sh` treats a
nonzero KAT result as the expected phase-1 witness and fails if production
unexpectedly appears GREEN.

The current implementation reproduced nineteen contract gaps:

- MFN1 offer/accept still use 62/63 instead of 52/53.
- Fourteen transfer message types still use 64..77 instead of 54..67.
- NRC1 still uses 204-byte slots, 14732 value bytes, and 14768 logical bytes
  instead of 208 / 15020 / 15056.

This RED is intentional. Production files under `src/runtime/mfdt_v1/` were not
changed in phase 1.

## Verification

Run from repository root:

```sh
python3 tools/multi_frame_durable_transfer_spec_vector_gen.py --check
python3 tools/multi_frame_durable_transfer_spec_vector_gen.py --self-test
python3 tools/multi_frame_durable_transfer_spec_gate.py --check
python3 tools/multi_frame_durable_transfer_spec_gate.py --self-test
node tools/multi_frame_durable_transfer_spec_gate.mjs --check
node tools/multi_frame_durable_transfer_spec_gate.mjs --self-test
tools/mfdt_v1_contract_red.sh
```

Final sealed authority:

- ADR SHA-256:
  `3e41c8ab13faef817b58dd6d7f1072be1746acea7898a4c6904434cb063b5a32`
- Generator SHA-256:
  `cc10561edce528bb9b8094383c18911116e6c30deabe34a9e405789c21c1ece6`
- Vector SHA-256:
  `fdd6fb87101bf9241785e5cbc02e5dbf56f83ab01360da140996f183b4a12b50`
- Authority-map SHA-256:
  `f7c24b9828108f8e8bba0310c999ce232a3c8ab8d18e2d936a6f1687873ad111`

Final result:

- Generator check/self-test: PASS
- Python gate check/self-test: PASS, 93/93
- Node gate check/self-test: PASS, 93/93
- C11 gate check/self-test: PASS, 93/93
- Four-system acceptance gate check/self-test: PASS
- Fresh CMake configure/build + dedicated MFDT CTest suite: PASS, 10/10
- Standalone production contract KAT: expected RED reproduced, 19 gaps

## Next GREEN tranche

Implementation order is deliberately fixed:

1. Update message allocation and MFN1 session constants; update codec/pipeline
   KATs without compatibility aliases for the void allocation.
2. Add NRC1 slot `session_generation`, migrate all readers/writers, and reject
   CRC-valid semantic mutants.
3. Replace the process-global single owner with the exact four-slot Host
   coordinator, deterministic restart allocation, and cyclic fairness.
4. Implement checked deadline/epoch behavior, canonical expiry NM30, exact
   retention boundary, and full restart semantic validation.
5. Re-run normal, sanitizer, crash/restart, Host four-transfer, ESP single-slot,
   and standalone contract KATs. Only then may `CONTRACT_FIXED_RED` move toward
   implementation GREEN or ADR acceptance review.

No release, public ABI, HIL, or SPEC_ACCEPTED claim is made here.
