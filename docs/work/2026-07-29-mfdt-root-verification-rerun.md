# MFDT root verification rerun

Date: 2026-07-29  
Scope: private/default-OFF Multi-frame Durable Transfer candidate

## Outcome

The root integration owner independently rebuilt and reran the checked-in MFDT
software evidence after the implementation tranche:

- Host normal: **26/26 PASS**
- Host ASan + UBSan: **26/26 PASS**
- Python, Node, and C specification oracles: **PASS** (93 vectors)
- Acceptance inventory and mutation self-test: **PASS**
- U5/U6 v2 freeze non-interference and mutation self-test: **PASS**
- Footprint, ESP DRAM self-test, tests-OFF/install boundary: **PASS**
- Runtime probe archive: **PASS**

The 26-test set includes wire/record KATs, lifecycle reuse, transactional
faults, restart and COMMIT_UNKNOWN classification, runtime pipeline, media
custody, two-endpoint transport simulation, ESP-store host conformance, and the
honest HIL runner.

## Commands

```sh
cmake -S . -B build-root-mfdt-final-normal \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON
cmake --build build-root-mfdt-final-normal -j
ctest --test-dir build-root-mfdt-final-normal \
  -R '^(mfdt_v1_|multi_frame_durable_transfer_)' --output-on-failure

cmake -S . -B build-root-mfdt-final-sanitizers \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON
cmake --build build-root-mfdt-final-sanitizers -j
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
ctest --test-dir build-root-mfdt-final-sanitizers \
  -R '^(mfdt_v1_|multi_frame_durable_transfer_)' --output-on-failure
```

## Remaining evidence

- The actual 4096-byte MFDT-over-Fabric path must be rerun after the current
  Fabric/Wi-Fi permit-authority repair is stable.
- The pinned ESP-IDF final-ELF/map proof must be rerun after shared target
  sources stop changing.
- Physical power-cut and transport HIL remain **NOT_RUN**. This record does not
  promote ADR-0021 or claim `HIL_VERIFIED` / `RELEASE_SUPPORTED`.
