# Multi-frame Durable Transfer SPEC-ONLY authority repair

> **Superseded for current status (2026-08-01):** this record remains audit
> history. Current SPEC_ACCEPTED status and evidence are in
> `docs/work/2026-08-01-mfdt-spec-accepted-promotion.md`. Historical Proposed
> wording below is not the live status authority.

Date: 2026-07-29  
Status: **Proposed SPEC-ONLY candidate repair — not SPEC_ACCEPTED; private default-OFF implementation candidate present (not public ABI / not HIL)**

## Semantic P1 closures (Sol Proposed audit)

| Topic | Decision | Evidence |
| --- | --- | --- |
| Terminal FSM vs BOTH=CORRUPT | Durable active codes exclude 7/9/39; terminal is NM30-only after G_*_TERMINAL erase+put | ADR state table; `MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE`; crash `MF-TX-TERMINAL-CRASH-ACTIVE-ONLY` / `NM30-ONLY`; existing `MF-CU-TERMINAL-GROUP-BOTH` |
| Request-id / complete=0\|1 | **Durable NRC1** (not RAM): 20-byte key, **15020-byte 72-slot** value (208 bytes/slot, generation-aware); **reachable max 65** (N_complete=65, N_abort=64; naive union 57 rejected); timeout retry max 8; fixed-16 rejected; OPEN digest = SHA-256(type‖len‖full body) no BIND52 strip | ADR NRC1 § reachable-path proof; `MF-POS-REQID-REACHABLE-MAX-COUNT`, `MF-POS-REQID-MAX-RETRY-TRACE`, layout/max-41/cache-full/OPEN-digest/budget vectors |
| Mid-transfer epoch change | Fence → NM30 CORRUPT_FENCED reason 0x8002; reclaim reservation; no prepare | `MF-NEG-EPOCH-CHANGE-MID-TRANSFER`, `MF-TX-EPOCH-CHANGE-TERMINAL` |
| S1–S6 + MF-O01 | Normative S1–S6 trace; Accepted control catalog remains 1/2 and independent private MFDT protocol v1 carries MFN1/MFDT (no re-freeze of docs/23·25·26) | `MF-TRACE-S1-S6-HAPPY-PATH`; current closure is recorded by the 2026-08-01 promotion |

## Purpose

Close independent NO-GO audits against ADR-0021 multi-frame durable custody
with a product-neutral, implementation-ready specification candidate and machine
authority. This record does not accept the ADR, update the compatibility matrix,
or claim HIL / RELEASE_SUPPORTED / production implementation / implementation complete.

## Authority systems (exactly four)

| # | System | Path |
| --- | --- | --- |
| 1 | Generator oracle | `tools/multi_frame_durable_transfer_spec_vector_gen.py` |
| 2 | Python gate | `tools/multi_frame_durable_transfer_spec_gate.py` |
| 3 | Node gate | `tools/multi_frame_durable_transfer_spec_gate.mjs` |
| 4 | C11 gate + literal KATs | `tests/model/multi_frame_durable_transfer_c_gate_test.c` (+ `..._c_authority.h`) |

Plus independent **acceptance gate** binding work/CMake/4-tool inventory:
`tools/multi_frame_durable_transfer_acceptance_gate.py`.

## CMake SPEC-ONLY tests (exactly ten)

Dedicated authority file: `cmake/ninlil_mfdt_ctest.cmake` (included from root
CMakeLists under tests-ON). Acceptance gate pins this file + its canonical
semantic inventory SHA — **not** whole-repo `CMakeLists.txt` — so unrelated
feature wiring cannot invalidate MFDT.

1. `multi_frame_durable_transfer_vector_oracle`
2. `multi_frame_durable_transfer_vector_oracle_self_test`
3. `multi_frame_durable_transfer_python_gate`
4. `multi_frame_durable_transfer_python_gate_self_test`
5. `multi_frame_durable_transfer_node_gate`
6. `multi_frame_durable_transfer_node_gate_self_test`
7. `multi_frame_durable_transfer_c_gate`
8. `multi_frame_durable_transfer_c_gate_self_test`
9. `multi_frame_durable_transfer_acceptance_gate`
10. `multi_frame_durable_transfer_acceptance_gate_self_test`

Registered only under `NINLIL_BUILD_TESTS=ON`. Not install()-exported. Not in
tests-OFF private production target claims.

## Audit closures (candidate level)

| Finding | Closure |
| --- | --- |
| Prior semantic/budget/CU findings | See earlier sections / ADR-0021 candidate text |
| Metadata hard-pin P1 | adr/title/sources/nonclaims + source digests in seal |
| **P1: no independent C gate / byte KAT** | C11 gate parses vector independently; literal ONE-BYTE wire KATs + 93-ID status/classification/bounds; rejects coherent vector drift vs C literals |
| **P2: seal unbound from work/CMake** | Acceptance gate hard-pins Proposed work Status, 10 CMake test names, 4 tools, noninstall; permanent mutants for Status→SPEC_ACCEPTED and Node self-test removal |
| **P0: NRC1 capacity/liveness** | **retry_budget SM** (owner=requestor, init=8, decrement=new-ID timeout retry, exhaustion forbids new-ID only; per-transfer/per-side). Reachable IDs **derived from SM**: N_complete=65, N_abort=64, max=65. Capacity **72 slots / 15020 value bytes / 15056 logical bytes**. FINALIZE success ⊥ ABORT success. Vectors: SM + reachable-max + max-retry-trace |
| **P1: terminal late-dup vs NRC1 erase** | **NRC1 retained until NM30 retention GC** (not erased at terminal). Post-terminal bit-exact hit; after GC closed `transfer_expired`. FULL max-ID path **77/67** (receiver/sender). Daily **154/134**. KATs: terminal late-dup matrix, terminal restart late-dup, post-retention expired |

## Non-claims

- Not SPEC_ACCEPTED / Accepted / RELEASE_SUPPORTED
- Not implementation complete or public ABI
- Not HIL / power-cut success
- Not compact RF or Wi-Fi multi-frame carriage
- Not docs/25·26 already re-frozen
- Not a status promotion of this SPEC candidate

## Artifacts

| Path | Role |
| --- | --- |
| `docs/adr/0021-multi-frame-durable-custody.md` | Proposed candidate |
| `spec/vectors/multi-frame-durable-transfer-spec-v1.json` | Machine authority |
| `tools/multi_frame_durable_transfer_spec_vector_gen.py` | Generator |
| `tools/multi_frame_durable_transfer_spec_gate.py` | Python gate |
| `tools/multi_frame_durable_transfer_spec_gate.mjs` | Node gate |
| `tests/model/multi_frame_durable_transfer_c_gate_test.c` | C11 gate |
| `tests/model/multi_frame_durable_transfer_c_authority.h` | C literal authority |
| `tools/multi_frame_durable_transfer_acceptance_gate.py` | Acceptance bind |
| `docs/work/2026-07-29-multi-frame-durable-transfer-spec-repair.md` | This record |
| `CMakeLists.txt` | 10 focused tests (tests-ON only) |

## Verification

After any normative ADR/work/CMake/C-authority edit, resync hardpins through the
single generator authority (do not invent digests by hand):

```text
python3 tools/multi_frame_durable_transfer_authority_resync.py
```

Then:

```text
python3 tools/multi_frame_durable_transfer_spec_vector_gen.py --check
python3 tools/multi_frame_durable_transfer_spec_vector_gen.py --self-test
python3 tools/multi_frame_durable_transfer_spec_gate.py --check
python3 tools/multi_frame_durable_transfer_spec_gate.py --self-test
node tools/multi_frame_durable_transfer_spec_gate.mjs --check
node tools/multi_frame_durable_transfer_spec_gate.mjs --self-test
# C gate (after build):
#   ninlil_multi_frame_durable_transfer_c_gate_test --check|--self-test <repo>
python3 tools/multi_frame_durable_transfer_acceptance_gate.py --check
python3 tools/multi_frame_durable_transfer_acceptance_gate.py --self-test
ctest -R 'multi_frame_durable_transfer_' --output-on-failure   # 10/10
# normal + ASan/UBSan focused; tests-OFF configure/install
```

## Private implementation (default-OFF) — 2026-07-29 continuation

Status of **spec** remains **Proposed SPEC-ONLY** (not SPEC_ACCEPTED). This section
records the **private host/lab implementation candidate** only. Public ABI is
unchanged. Default is OFF.

### Scope delivered

| Area | Result |
| --- | --- |
| Private API prefix | `ninlil_mfdt_v1_*` in `src/runtime/mfdt_v1/` |
| Sender segmentation | OPEN → pages → chunks → FINALIZE (geometry 0..32768, 896/chunk, 37 max) |
| Receiver reassembly | OPEN_ACCEPT → PAGE_ACCEPT → CHUNK_ACCEPT → TRANSFER_ACCEPT |
| Identities | transfer_id[16], request_id u64, request_body_digest = SHA-256(type‖len‖body) |
| NRC1 | durable 72-slot / 208-byte slot / 15020-byte value; retained until retention GC; late-dup hit |
| FULL / wear | lab FULL counter; repaired contract asserts ≤ rx 77 / tx 67 |
| CU | exact OLD/NEW/PARTIAL/EXTRA/THIRD/ABSENT/BOTH classifier |
| No partial publish | publication_ready only after whole digest verified (or empty OPEN) |
| Abort / denied | ABORT_ACK pre-verify; REJECT ABORT_DENIED post content-verified |
| Crash inject | `lab_store.crash_after_fulls` fails next FULL commit |
| Cold-restart (lab) | store durable in-process; restart_scan clears volatile publish flags |
| GC | `retention_gc` deletes NM30+NRC1 together → `transfer_expired` |
| FRAG / Fabric / AppData | boundary header only (`mfdt_v1_boundary.h`); no public ABI change |
| ESP | Kconfig `NINLIL_ENABLE_MFDT_V1_PRIVATE` default n; component append when ON |
| radio_hil_app | `MFDT_PING` / `MFDT_STATUS` / `MFDT_*` stubs → residual H50 hardware |

### Sources (authority)

| Path | Role |
| --- | --- |
| `cmake/ninlil_mfdt_v1_sources.cmake` | production vs lab source lists |
| `cmake/ninlil_mfdt_v1_ctest.cmake` | private host CTest (only if `NINLIL_ENABLE_MFDT_V1_PRIVATE=ON`) |
| `src/runtime/mfdt_v1/mfdt_v1.h` | private API |
| `src/runtime/mfdt_v1/mfdt_v1_crypto.c` | SHA-256, CRC32C, geometry, digests, CU |
| `src/runtime/mfdt_v1/mfdt_v1_store.c` | lab FULL simulator + crash inject |
| `src/runtime/mfdt_v1/mfdt_v1_engine.c` | FSM, NRC1, sender/receiver |
| `src/runtime/mfdt_v1/mfdt_v1_boundary.h` | AppData/FRAG/Fabric non-ABI notes |
| `tests/runtime/mfdt_v1/mfdt_v1_unit_test.c` | unit |
| `tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c` | E2E min/max/boundaries/abort/crash/reorder |
| `tests/runtime/mfdt_v1/mfdt_v1_lifecycle_test.c` | 10k empty lifecycle reuse |

Enable (host):

```text
cmake -S . -B build-mfdt-private \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON \
  -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake --build build-mfdt-private --target \
  ninlil_mfdt_v1_unit_test ninlil_mfdt_v1_e2e_test ninlil_mfdt_v1_lifecycle_test
ctest --test-dir build-mfdt-private -R 'mfdt_v1_' --output-on-failure
```

ASan/UBSan:

```text
cmake -S . -B build-mfdt-asan \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON \
  -DNINLIL_ENABLE_SANITIZERS=ON \
  -DNINLIL_ENABLE_STRICT_WARNINGS=ON
cmake --build build-mfdt-asan --target \
  ninlil_mfdt_v1_unit_test ninlil_mfdt_v1_e2e_test ninlil_mfdt_v1_lifecycle_test
./build-mfdt-asan/ninlil_mfdt_v1_unit_test
./build-mfdt-asan/ninlil_mfdt_v1_e2e_test
./build-mfdt-asan/ninlil_mfdt_v1_lifecycle_test
```

### Commands / results (this tranche)

| Command | Result |
| --- | --- |
| Host unit (`mfdt_v1_unit_test`) | **OK** |
| Host E2E (`mfdt_v1_e2e_test`) — empty, 1B, 896, 897, 22×896, 22×896+1, 32768; abort; crash inject; digest conflict; reorder | **OK** |
| Host lifecycle 10k (`mfdt_v1_lifecycle_test`) | **OK** |
| ASan/UBSan unit+e2e+lifecycle | **OK** (ASAN_EXIT:0) |
| `ctest -R 'mfdt_v1_'` private build+3 tests | **4/4 Passed** |
| `ctest -R 'multi_frame_durable'` SPEC 10 | **10/10 Passed** (83/83 authority unchanged) |
| Default OFF (`NINLIL_ENABLE_MFDT_V1_PRIVATE` unset) | private lib/tests not in default ALL build |

### P0 freeze non-interference (2026-07-29)

Accepted U5/U6 v2 freeze and R6 docs/25 must not be rewritten by independent private MFDT v1.

| Surface | Pin | Status |
| --- | --- | --- |
| `spec/frozen/u5-u6-normative-freeze-v2.json` | sha256 `deff647c…ea7e783`, 4299 bytes | **unchanged** |
| `docs/25-…` | 50405 / `ba62b2c7…41e71a` | **byte-exact** (no 50896 expand) |
| `docs/26-…` | 58152 / `f68b7008…0edc59` | **byte-exact** |
| ADR-0005 / ADR-0006 | freeze table | **byte-exact** |
| `docs/23-…` | 155916 / `adaf5cd1…536a34` | **byte-exact** baseline pin |
| private MFDT protocol v1 | ADR-0021 only | separate from Accepted control 1/2; **no** freeze-doc table |

Gate (always under tests-ON; not part of the 10-test MFDT SPEC inventory):

```text
python3 tools/mfdt_freeze_noninterference_gate.py check
python3 tools/mfdt_freeze_noninterference_gate.py self-test
```

CTest: `mfdt_freeze_noninterference_gate` + `_self_test`.

### Honest residuals (hardware / production)

| Residual | Why open |
| --- | --- |
| Power-cut HIL | Lab crash inject only; no physical flash power-cut run |
| RF HIL / H50 physical | radio_hil_app stubs only (`MFDT_*` → residual); no RF multi-frame carriage proof |
| ESP final-ELF/map all-feature ON | Component/Kconfig wired; full IDF all-feature image/map gate not executed in this host tranche |
| Flash durable adapter | Engine uses lab in-memory FULL store; ESP production flash NM3*/NRC1 driver not bound |
| Bit-exact BIND52 wire vs vector KATs | Lab wire preserves identities/digests/FSM; full BIND52 response layouts are candidate-aligned, not vector byte-identical |
| SPEC_ACCEPTED / RELEASE_SUPPORTED | **Not claimed** — still Proposed SPEC-ONLY + private default-OFF |
| Public support status | MFDT remains private/default-OFF; not install()-exported; not public ABI |

### Non-claims (implementation)

- Not SPEC_ACCEPTED, not RELEASE_SUPPORTED, not public OSS headers
- Not power-cut success, not RF HIL pass, not Japan legal / field-ready
- Not FRAG multi-frame durable equivalence; FRAG remains orthogonal
- Not Application Receipt ownership (upper only after handoff)
