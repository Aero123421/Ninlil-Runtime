# MFDT repaired contract: single-engine software GREEN

Date: 2026-07-30  
Status: **SOFTWARE_GREEN / PRIVATE_DEFAULT_OFF / PROPOSED_SPEC_ONLY**  
Scope: the ADR-0021 private, exact-one-transfer engine and its direct
wire/storage/runtime tests. The four-slot Host coordinator is a separate
composition of four caller-owned engines and is not claimed by this record.

## Outcome

The phase-1 executable RED witness is now registered as
`mfdt_v1_contract_green` and passes against the production private sources.
The repaired contract has one live interpretation:

- MFN1 occupies `0x34..0x35`; the fourteen MFDT messages occupy
  `0x36..0x43`. There are no compatibility aliases for the void allocation.
- NRC1 is 72 fixed 208-byte slots, 15020 value bytes, and 15056 logical
  bytes. Replay identity is exactly `(session_generation, request_id)`.
- One `ninlil_mfdt_v1_engine_t` owns exactly one active transfer on Host and
  ESP. A different second transfer returns BUSY/CAPACITY with no FULL and no
  incumbent mutation.
- Session-generation advance is one atomic durable reset. A failed FULL
  restores the prior generation and replay state; the same numeric request ID
  in the next generation cannot hit the previous generation's response.
- Wire ABORT, ABORT_ACK, and terminal NM30 behavior follow the repaired
  contract. Expiry creates canonical `ABORTED / EXPIRED(5)` terminal state.
- Reservation arithmetic is checked. Same-epoch expiration, a foreign clock
  epoch, and overflow all fail without durable mutation.
- Retention GC uses the exact inclusive boundary and erases retained NM30 and
  NRC1 together.
- Restart validates ACTIVE, NRC1, and NM30 semantics after CRC validation;
  CRC-repaired semantic mutants are rejected.
- Sender acceptance evidence is durable and required for the terminal state.
- Caller-provided ApplicationData identity and service/deadline metadata are
  encoded byte-exact, survive cold restart, and reissue byte-exact.
- Operational engine/spine/ESP-store paths do not grow the heap. Fixed scratch
  is prepared at startup, allocation failure is fail-closed, and a monotonic
  allocation-attempt counter proves no operational allocation after init.

## Direct acceptance evidence

The direct tests cover:

- wire constants and the repaired contract witness;
- exact caller metadata offsets, manifest binding, cold restart, and OPEN
  reissue;
- second-transfer response isolation and incumbent NRC1 replay preservation;
- session generation rollback/advance and generation-local replay;
- deadline epoch, expiry, reservation overflow, and retention boundaries;
- exact ABORT/ABORT_ACK/NM30 behavior;
- semantic ACTIVE restart mutants with both CRC layers repaired;
- durable FULL crash/rollback and COMMIT_UNKNOWN behavior;
- startup OOM, ESP bind OOM, and post-init no-growth allocation checks;
- 10,000 lifecycle transfers;
- install-symbol, footprint, ESP-map dry-run, and honest HIL-NOT_RUN gates.

Fresh normal build:

```sh
cmake -S . -B /tmp/ninlil-mfdt-green \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON
cmake --build /tmp/ninlil-mfdt-green \
  --target ninlil_multi_frame_durable_transfer_c_gate_test
ctest --test-dir /tmp/ninlil-mfdt-green \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure
```

Result: **27/27 PASS** (10 sealed authority tests + 17 private tests).

Fresh ASan/UBSan build:

```sh
cmake -S . -B /tmp/ninlil-mfdt-green-asan2 \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build /tmp/ninlil-mfdt-green-asan2 \
  --target ninlil_multi_frame_durable_transfer_c_gate_test
ASAN_OPTIONS=halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
ctest --test-dir /tmp/ninlil-mfdt-green-asan2 \
  -R '^(multi_frame_durable_transfer_.*|mfdt_v1_.*)$' \
  --output-on-failure
```

Result: **27/27 PASS**, with no ASan or UBSan finding.

## Sealed authority

- ADR SHA-256:
  `4f89452e41d645cb06520aa7e223267c75e30bed26dd4e1c47d4bfdb2b52c744`
- Generator SHA-256:
  `97fdcb87570759a9fb71f289922f0995b675e7bf4a5bb1ca2454bd0b8ee4df74`
- Vector SHA-256:
  `9237eae69e139d8a22360ca46242bc731c643893d5ded645ce53c33e6667ff61`
- Authority-map SHA-256:
  `e598ef11bc9c42da335218f9e01881e29bbe805948fa33d8d1c2190a3b72a6d9`

## Remaining boundary and non-claims

- Physical ESP32-S3 power-cut HIL remains **NOT_RUN**. It is not represented by
  the passing software HIL runner.
- MFDT remains private, source-only, default-OFF, not installed, and outside
  the public ABI.
- This record does not promote ADR-0021 to Accepted or MFDT to default-ON.
- The four-active-transfer Host profile requires the separate four-engine
  coordinator acceptance tranche; this single-engine record does not claim it.
- Compact SX1262 physical carrier E2E remains outside this software record.

Within the single-engine repaired-contract tranche there is no known remaining
software RED. Shared engine source is frozen for coordinator integration unless
that integration exposes a reproducible contract defect.
