# MFDT unattested NRC1 replay repair / review

Date: 2026-07-30  
Scope: private / default-OFF Multi-frame Durable Transfer candidate  
Status: **Proposed / PROPOSED_SPEC_ONLY** — not `SPEC_ACCEPTED`, not HIL PASS,
not `RELEASE_SUPPORTED`

## Outcome

ESP-style `COMMIT_UNKNOWN` read-back `NEW` no longer becomes success on the
same request ID through a durable NRC1 hit while physical-HIL promotion is OFF.
The target now returns `ERR_COMMIT_UNKNOWN` with no response body for:

- retry in the same process;
- cold restart with active+NRC1;
- cold restart with NRC1 only;
- cold restart with retained NM30+NRC1.

This applies to mutation+NRC1 and NRC1-only FULL groups. Host FULL-capable
storage keeps bit-exact NRC1 replay. Accepted
`docs/26-u6-transport-custody.md` was not changed.

## Root cause and repair

`nrc1_try_hit()` / public `nrc1_lookup()` validated digest and cached bytes but
did not ask whether the local storage profile was allowed to expose those bytes
as FULL evidence. After the first target CU/NEW returned
`ERR_CU_NEW_NOT_PROMOTED`, the durable NRC1 therefore turned a retry into OK.

The repair:

1. adds one replay-eligibility boundary used by both internal and public NRC1
   paths;
2. propagates every negative NRC1 result from OPEN/PAGE/CHUNK/FINALIZE/RESUME/
   ABORT handlers;
3. returns `ERR_COMMIT_UNKNOWN` and zeroes the response for an unattested
   target hit;
4. treats real `ESP_PLATFORM` as target authority at compile time, so a
   caller-controlled `host_mode=1` cannot bypass the gate;
5. preserves Host FULL-capable replay and the existing exact digest-conflict
   behavior;
6. rejects oversized cached response lengths as corrupt before copying.

The machine vector `MF-CU-NRC1-NEW` now pins wire success `0`, target warm/cold,
active+NRC1, and NRC1-only results to `COMMIT_UNKNOWN`, while independently
pinning Host replay to `OK`. Python and Node gates assert the fields separately.

## Coverage matrix

| State / event | ESP target, gate OFF | Host FULL-capable |
| --- | --- | --- |
| First CU read-back exact NEW | adopt durable bytes for recovery; no wire success | not an unattested ESP event |
| Same-process same-ID NRC1 hit | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` |
| Cold active+NRC1 | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` |
| Cold NRC1-only | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` |
| Cold NM30+NRC1 late duplicate | `ERR_COMMIT_UNKNOWN`, empty response | bit-exact `OK` |

Exact media classification remains separately tested:

| Class | Result |
| --- | --- |
| OLD | retryable storage result; no NEW promotion |
| NEW | raw durable classification only; `ERR_CU_NEW_NOT_PROMOTED` |
| PARTIAL / EXTRA / THIRD | corrupt/unknown fence; never success |

The storage ABI restart contract is covered by the ESP adapter NULL-buffer
length probe and cold-restart tests.

## Attestation review

`ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation()` intentionally
has no enabling path in this candidate. NULL/empty input is an argument error;
all non-empty bytes return `ERR_STATE` and the gate remains OFF. Tests reject:

- a magic prefix with a zero tail;
- a magic prefix with a non-zero tail;
- opaque/digest-shaped non-zero bytes.

Adding a function pointer, weak hook, magic parser, or CI setter now would only
create another forge path. A trustworthy one-way enablement path first needs an
Accepted evidence schema and trust anchor, secure-boot-derived
device/build/profile binding, durable monotonic anti-rollback state,
expiry/revocation authority, negative rollback/revocation tests, pinned target
closure, and the physical power-cut matrix. ADR-0021 tracks this separately as
**MF-O08 OPEN / release blocker**. Therefore this work does not claim
“implementation complete; only physical HIL remains.”

## P0 / P1 / P2 review

| Finding | Severity | Disposition |
| --- | --- | --- |
| Unattested CU/NEW NRC1 retry became external success | P0 | **FIXED** — target warm/cold and every retained-state shape fail closed |
| Magic/non-zero bytes could be mistaken for an attestation contract | P1 | **FIXED** — no parser/verifier; forged forms have negative tests |
| Target caller could select Host replay with `host_mode` | P1 | **FIXED** — `ESP_PLATFORM` ignores the caller profile bit for replay authority |
| Positive Host vector did not state its storage profile; CU/NEW vector claimed wire success | P2 | **FIXED** — vector and independent Python/Node/C authorities updated |

Unresolved implementation findings in the repaired private/default-OFF
snapshot: **P0=0, P1=0, P2=0**. MF-O08 is an explicit production-promotion
release blocker, not silently counted as completed software or HIL evidence.
Independent SPEC acceptance review remains separate.

## Verification

Fresh Host normal inventory:

```sh
cmake -S . -B build-codex-mfdt-retry-normal \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON
cmake --build build-codex-mfdt-retry-normal -j4
ctest --test-dir build-codex-mfdt-retry-normal \
  -R '^(mfdt_v1_|multi_frame_durable_transfer_)' --output-on-failure
```

Result: **26/26 PASS**.

Fresh ASan + UBSan inventory:

```sh
cmake -S . -B build-codex-mfdt-retry-asan \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-codex-mfdt-retry-asan -j4
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
ctest --test-dir build-codex-mfdt-retry-asan \
  -R '^(mfdt_v1_|multi_frame_durable_transfer_)' --output-on-failure
```

Result: **26/26 PASS**. After the final ADR open-register update and authority
resync, all 10 spec/oracle/acceptance tests were rebuilt and rerun in both
normal and Sanitizer builds: **10/10 PASS** each.

Authority resync:

```text
vectors=93
ADR sha256=f2d2ea450cd16b80f08f54720452cd812908dc04bbac6e6c66b57fc266731203
generator sha256=9af5ac005c64eab073ae3e4ef487c0eb23662ce70082145219e75dfe3cfd9e6d
vector sha256=635f71c5833ee150376e8fd9edde8c18e3c9ca73ce193d0600de62801243959b
map sha256=ef32126ad828d57001792022d53ec1f4a6a4519b0bab48a930b6d7f3806c48f4
```

ABI / resource / footprint:

```text
installed libninlil_runtime.a MFDT symbols: 0
private runtime MFDT symbols: 306
workspace: 65536
lab_store: 116208
engine: 112
pipeline: 2208
spine_ctx: 184176
engine_scratch: 49715
```

Pinned target proof:

```sh
ESP_IDF_PIN=v5.5.3 bash tools/mfdt_v1_esp_idf_map_proof.sh
```

Result: **PASS** with ESP-IDF v5.5.3, ESP32-S3 final ELF/map, all required live
symbols, target smoke call path, no lab store in the map, and MFDT DRAM BSS
`963 / 49152` bytes. Firmware binary size was `0x52170` bytes.

Physical power-cut HIL: **NOT_RUN** (`no_serial_port_configured`). The generated
evidence keeps `full_esp_hil_attested=false` and
`physical_powercut_executed=false`.

## Files in this repair

- Proposed authority and generated gates/vectors:
  `docs/adr/0021-multi-frame-durable-custody.md`,
  `spec/vectors/multi-frame-durable-transfer-spec-v1.json`,
  `tools/multi_frame_durable_transfer_spec_vector_gen.py`,
  Python/Node/C/acceptance authority outputs.
- Private runtime:
  `src/runtime/mfdt_v1/mfdt_v1_engine.c`,
  `src/runtime/mfdt_v1/mfdt_v1_hil_gate.c`,
  `src/runtime/mfdt_v1/mfdt_v1.h`.
- Regression tests:
  `tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c`,
  `tests/runtime/mfdt_v1/mfdt_v1_esp_store_cu_test.c`.
- Contract note:
  `docs/work/2026-07-29-mfdt-esp-hil-promotion-contract.md`.

README and compatibility matrix were intentionally not changed; those remain
post-acceptance work.
