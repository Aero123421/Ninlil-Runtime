# Composable Public Runtime Modules T0 fresh closure review

Date: 2026-07-31  
Reviewer role: independent Codex subagent, review-only  
Decision: **NO-GO — P0=0 / P1=3 / P2=0**  
T0 software-contract closure: **not closed**  
Promotion performed: none

## Reviewed snapshot

This review is bound to the following working-tree bytes. The repository was
already a large uncommitted integration worktree, so this is not an immutable
commit receipt.

| Path | SHA-256 |
| --- | --- |
| `docs/adr/0028-composable-public-runtime-modules.md` | `fe7b84cd1a01d09c9bde4149759b1b04dcdcc4b4d8a185dde11c0314838645bc` |
| `public-module-manifest.json` | `8cf43b8c33770999b88754b43f8b98a438a8e9bdc4e37137bdc2780ea30f33fd` |
| `spec/public-module-manifest-v1.schema.json` | `c4144b31a90a96578ae7b567a9b82672e7ff5afa82c61defecf648f5e1705671` |
| `tools/public_module_manifest_gate.py` | `9eebd632e4099a52c11a6ee5fc1700e28906bb2b9a73f68a8aa9248987cc21bd` |
| `compatibility-matrix.json` | `7bbaec4d550522245c4749d3f0b4b599f50d9bca4894b907e48fdb070eec6fa4` |
| `tools/compatibility_matrix_gate.py` | `de33bef908e67bdd0ab38be29bc095320374009bbf523f268532b750afaf9f00` |
| `CMakeLists.txt` | `c0ad415c33848ff5200b6180c80b2070983d0f6b4153893bf3361bb00e316485` |
| `.github/workflows/ci.yml` | `e931c74d4082f4545673e7960a54431c66a61e51c46942d08ca7aac82c733ed8` |
| repair record | `789280b39a922139b0ba31d8eb395cd37789dfc9127c3be318e1315f846bf198` |

## Confirmed conservative state

- ADR-0028 is still `Proposed`.
- All eight modules are exactly `PRIVATE_CANDIDATE`.
- All eight package entries are exactly `ABSENT`.
- All module-specific normative specifications are `NOT_CREATED`; all module
  reviews and separation checks are `NOT_RUN`.
- The 17 module rows plus two cross-module rows are all `NOT_RUN` for test,
  evidence, and HIL. No row claims `PASS`.
- The declared public header roots and exact public CMake targets are absent.
  Existing similarly named build targets remain private/default-OFF candidates.
- Identity/Attachment, Fabric selection, restart checkpoint, replay receipt,
  and independent-review contracts match their schema `const` values. Their
  canonical JSON SHA-256 values are respectively:
  `d1378940…c599`, `a09bdb41…8d30`, `292c91b5…2eaf`,
  and `26ff8b72…cab4`.
- A GO review is rejected both when implementer separation is unverified and
  when it is marked verified, because the OIDC provenance offline verifier is
  intentionally not implemented.

These facts mean the current manifest does not falsely claim public packages,
hosted CI receipts, OIDC verification, target execution, physical HIL, or
release support. They do not close the future-promotion false greens below.

## P1-1 — the eight module and 19-row exact contracts are not sealed

`EXPECTED_MODULES` pins IDs, package metadata, platform rosters, feature
mappings, symbol prefixes, dependency rosters, and acceptance IDs. However,
the gate only type-checks `wire_profiles` and `storage_schemas`, generically
validates namespace shape, and accepts any non-empty acceptance requirement
and any pattern-matching test path.

Independent in-memory mutants accepted by `check`:

- append `BOGUS-WIRE` to Fabric `wire_profiles`;
- append `BOGUS-STORAGE` to MFDT `storage_schemas`;
- replace Fabric physical namespace and partition with unrelated unique values;
- remove the substantive Fabric multi-instance acceptance semantics while
  retaining only the few searched tokens;
- retarget `PM-FAB-ABI-01` to an arbitrary nonexistent
  `tests/public_modules/trivial_abi_negative.c` while it remains `NOT_RUN`.

Primary evidence:

- `tools/public_module_manifest_gate.py:1724`
- `tools/public_module_manifest_gate.py:1733`
- `tools/public_module_manifest_gate.py:2199`
- `tools/public_module_manifest_gate.py:2203`

Risk: the machine authority can silently change wire/storage/ownership or
weaken and retarget an acceptance row without changing its stable ID, while
the schema and gate remain green. This contradicts the requested exact
eight-module and 19-row authority.

Required close: pin the full per-module contract and the complete acceptance
ledger by exact keyed values or canonical contract digests, including
wire/storage namespace, writer/driver policy, requirement text, test path, HIL
classification, and cross-module coverage. Add coherent mutants for every
field family above.

## P1-2 — a replay receipt is not bound to the declared test source

The manifest says an active CTest command must match the declared test path.
The implementation only searches the registration file for
`add_test(NAME <acceptance-id> ...)`, then accepts any root-confined executable
from the configured CTest catalog except files literally named `echo`, `true`,
or `false`. It compares the declared test file bytes and registration file
bytes to the tested commit, but never proves that the configured executable
was built from, invokes, or otherwise owns that test file.

An independent probe confirmed that
`add_test(NAME PM-FAB-ABI-01 COMMAND unrelated_always_pass)` satisfies
`has_ctest_registration`. The existing self-test covers absent/commented,
`echo`, and disabled entries, but has no registered unrelated root executable
mutant.

Primary evidence:

- `public-module-manifest.json:320`
- `tools/public_module_manifest_gate.py:780`
- `tools/public_module_manifest_gate.py:2493`
- `tools/public_module_manifest_gate.py:2587`
- `tools/public_module_manifest_gate.py:2646`

Risk: a trivial zero-exit executable can produce a replayable, digest-correct
`PASS` receipt for a substantive acceptance source that never ran.

Required close: bind each acceptance ID to an exact CMake target and use the
CMake File API codemodel or an equivalent closed build manifest to prove that
the configured test command owns the declared source/runner. For script
runners, bind the exact interpreter, script path, arguments, and bytes. Add a
root-confined unrelated-always-pass executable mutant.

## P1-3 — platform/profile provenance is only a self-reported label

Evidence validation checks only that `platform_id` is in the module's declared
platform roster. The CMake cache check proves the source root, but does not bind
the receipt to OS, architecture, compiler/toolchain, build type, sanitizer
profile, ESP-IDF target/version, or final ELF/map. A ledger row holds only one
evidence object and therefore cannot represent the Debug/Release,
GCC/Clang, sanitizer, and per-platform matrix required by ADR-0028 section 9.

This is especially unsafe for `PM-WIFI-ESP-ABI-01`, whose requirement includes
an ESP component and final ELF map: a local Host CTest tree can label its
receipt `esp32s3-esp-idf` without a target-toolchain proof.

Primary evidence:

- `tools/public_module_manifest_gate.py:2424`
- `tools/public_module_manifest_gate.py:2498`
- `public-module-manifest.json:313`
- `docs/adr/0028-composable-public-runtime-modules.md:525`

Risk: Host success can be relabeled as ESP or as an unexecuted compiler/profile
matrix and then satisfy the single-row `PACKAGE_EXPERIMENTAL` PASS check.

Required close: replace the free platform label with a verified build-profile
receipt. Bind source commit/tree, OS/arch, compiler and toolchain identity,
build type, sanitizer mode, CMake cache/profile, and for ESP the pinned ESP-IDF
target plus final ELF/map digests. Represent and require every declared
non-HIL platform/profile receipt before package promotion.

## Independently reproduced green checks

```text
python3 tools/public_module_manifest_gate.py check
python3 tools/public_module_manifest_gate.py self-test
  PASS / PASS

python3 tools/compatibility_matrix_gate.py check
python3 tools/compatibility_matrix_gate.py self-test
  PASS / PASS

cmake -S . -B build/public-modules-fresh-closure-review \
  -DNINLIL_BUILD_TESTS=ON -DNINLIL_ENABLE_STRICT_WARNINGS=ON
  PASS (AppleClang 21, macOS arm64 local configuration)

python3 tools/public_module_manifest_gate.py verify-ctest-registration \
  --build-dir build/public-modules-fresh-closure-review
  PASS

configured focused CTest:
  compatibility_matrix_gate
  compatibility_matrix_gate_self_test
  public_module_manifest_gate
  public_module_manifest_gate_self_test
  4/4 PASS, exact once, none DISABLED
```

Semantic YAML parsing confirmed that `ubuntu-dynamic-strict` on
`ubuntu-24.04` and `macos-dynamic` on `macos-15` each contain the active
registration verifier, focused public-module CTest, and subsequent full CTest
with no step/job condition. This proves workflow registration only. No fresh
GitHub-hosted Ubuntu/macOS run receipt was obtained.

Independent negative probes correctly rejected H1 substitution, path
traversal, an actual symlink path component, manifest/matrix bool-as-int,
Fabric stale fallback, Identity changed-floor mask drift, checkpoint CRC
polynomial drift, schema `const` digest drift, fabricated `PASS`, unverifiable
HIL `PASS`, and unverified/fabricated review GO.

## Non-claims

- No public module implementation, header, target, component, or package was
  created or accepted by this review.
- No acceptance row, hosted CI receipt, OIDC attestation, ESP on-target run,
  public package, or physical HIL was executed or promoted.
- Identity/Fabric/checkpoint contract digests being internally consistent does
  not prove their future implementations.
- The current conservative `PRIVATE_CANDIDATE` / `ABSENT` / `NOT_RUN` state is
  honest, but T0 software-contract closure remains **NO-GO** until all three P1
  findings are repaired and independently re-reviewed.
