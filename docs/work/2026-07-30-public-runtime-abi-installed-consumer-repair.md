# Public Runtime ABI and installed-consumer repair — 2026-07-30

Status: **HOST NORMAL + ASAN/UBSAN PASS / PHYSICAL HIL NOT_RUN**

## Scope

This tranche closes the public, installed-package evidence for ADR-0027
without promoting that ADR from Proposed:

- the primary Controller, Endpoint, Cell Agent, Test, Lab, Field, and
  Production constants are part of the ABI inventory and golden manifest;
- the earlier `*_RESERVED` spellings remain source-compatible aliases with
  exact value equality;
- `NINLIL_FOUNDATION_MAX_EXACT_TARGETS == 4` is protected by the normative
  ABI, manifest inventory, and C11/C++17 public-header smoke tests;
- a consumer built only against a fresh `NINLIL_BUILD_TESTS=OFF` install
  exercises the Runtime through public headers and installed CMake targets.

No application-specific vocabulary or private Runtime/test helper is used by
the installed consumer. Physical USB, radio, and ESP32-S3 HIL are outside this
Host/package tranche and remain `NOT_RUN`.

## Installed consumer contract

The clean consumer proves all of the following:

1. Runtime create/destroy for 3 roles × 4 environments.
2. Unknown role/environment rejection.
3. Cell Agent creation with application Service registration failing closed
   as `NINLIL_E_UNSUPPORTED`.
4. Controller DesiredState admission for exact 4-target and 2-target rosters.
5. Canonical roster ordering and deep copy after all caller-owned target,
   idempotency-key, and payload buffers are overwritten.
6. `NINLIL_E_BUFFER_TOO_SMALL` with the required target count and no partial
   target projection.
7. Idempotent replay, changed-content conflict, query, list, and capacity
   visibility.
8. Bounded target-local retry progress: one one-transition step cannot consume
   retry state for every target.
9. Destroy/recreate recovery and, for SQLite, a cold provider reopen before
   service reattachment, query/list, roster, counter, revision, and replay
   verification.
10. Existing four-Service EventFact lifecycle evidence remains intact.
11. The installed headers and `Ninlil::runtime` compile and link from strict
    C11 and C++17 consumers.

The producer side is checked with `ctest -N` and must contain zero tests.
SQLite-OFF remains free of SQLite targets, headers, and archives; SQLite-ON
must export the optional provider. Installed metadata and the consumer compile
graph must not refer to source/private/test paths.

## Red evidence that prevented a false green

Before the target-local production repair, the new public consumer failed
after one bounded Runtime step:

```text
retry isolation mismatch: attempted_targets=4 cumulative=4
per_target=[1,1,1,1]
```

Admission, deep-copy, query, replay, and conflict checks had already passed,
so the failure isolated the issue to retry-state ownership. The gate stayed
red until the shared production repair made the same scenario report at most
one target attempt for one state-transition budget.

## Final evidence

Fresh ABI/public-header matrix:

```text
ctest --test-dir build/agent-public-abi --output-on-failure -j 8 \
  -R '^(smoke_c11|smoke_cxx17|self_contained_(version|platform|service|transaction|runtime|byte_stream)_(c11|cxx17)|abi_drift_check|abi_drift_negative|abi_manifest_repeatable|abi_manifest_golden|abi_manifest_coverage)$'

100% tests passed, 0 tests failed out of 19
```

The independent drift tool reported:

```text
abi drift ok: macros=285 typedefs=45 structs=53 fields=526 callbacks=2 functions=14 manifest=(283,53,526)
```

Fresh normal tests-OFF installed-package matrix:

```text
ctest --test-dir build/agent-public-abi --output-on-failure -j 3 \
  -R '^host_runtime_tests_off_installed_consumer(_sqlite|_domain_on)?$'

100% tests passed, 0 tests failed out of 3
```

Fresh ASan/UBSan clean-install matrix:

```text
ctest --test-dir build/agent-public-abi-top-asan --output-on-failure -j 3 \
  -R '^host_runtime_tests_off_installed_consumer(_sqlite|_domain_on)?$'

100% tests passed, 0 tests failed out of 3
```

`NINLIL_ENABLE_SANITIZERS=ON` is forwarded into the tests-OFF producer and
the clean installed C11/C++17 consumers. This covers SQLite OFF, SQLite ON,
and the Domain-ON public-create fail-closed/installed-symbol variant. On
macOS, leak detection was explicitly disabled; ASan and UBSan still used
`halt_on_error=1`.

## Promotion boundary

These results are Host/package evidence, not physical HIL and not an
independent acceptance review. ADR-0027 therefore remains Proposed until its
documented review and promotion criteria are completed.
