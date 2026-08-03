# RRMP root verification rerun — 2026-07-29

## Scope

Root independently reran the private Route Relay / Multi-Parent candidate
matrix after adding the storage-atomicity, global-token-ledger and composition
tests to the completion CI entry point.

This is software evidence only. It does not promote ADR-0019 or ADR-0020,
publish the private API, or claim physical RF HIL.

## Results

| Profile | Required result | Observed |
|---|---|---|
| feature OFF residual | all registered residual tests | **15/15 PASS** |
| feature ON normal | all registered RRMP tests and gates | **16/16 PASS** |
| feature ON ASan/UBSan | codec, state machine, crash/corruption, storage atomicity, token ledger, lifecycle, composition | **7/7 PASS** |
| tests OFF, feature OFF | build/install without private paths | **PASS** |
| tests OFF, feature ON | build private archive; install remains public-only | **PASS** |
| frame/stack gate | ceiling 2048 bytes | **PASS** |
| storage ABI gate | exact callback ABI | **PASS** |
| physical multi-node RF HIL | real hardware | **NOT_RUN** |

Command:

```sh
NINLIL_CI_COMPLETION_JOBS=2 \
  bash tools/ci_completion_feature_host_matrix.sh rrmp all_profiles
```

The first run exposed a CI harness defect after every functional profile had
passed: the feature-ON/tests-OFF branch built only the
`EXCLUDE_FROM_ALL` private archive and then attempted to install optional
public archives that had not been built. The harness now builds the normal
install set and the private archive before installation. The corrected
boundary was rerun with:

```sh
NINLIL_CI_COMPLETION_JOBS=2 \
  bash tools/ci_completion_feature_host_matrix.sh rrmp tests_off_boundary
```

Result: `ci_completion_feature_host_matrix: PASS family=rrmp
profile=tests_off_boundary`.

The same generic install-harness repair was applied to the Fabric V1
feature-ON/tests-OFF boundary because it used the identical incomplete build
sequence. Fabric receives its own fresh rerun before final acceptance.

## Status

RRMP is **NO-GO** after independent authority review. All reported P1 defects
must be closed and independently re-reviewed before software acceptance is
recorded. Physical HIL remains explicitly `NOT_RUN`.

## Reopen follow-up: P1-2 / P1-4

The independent review returned `NO-GO (P0=0 / P1=6)`. The current verdict
remains `NO-GO` until `2026-07-29-rrmp-p1-repair-contract.md` is closed.

The obsolete storage-key authority and permissive dual-image import have now
been repaired:

- route physical keys = 21;
- parent physical keys = 22;
- NPP1 physical slots = 75, distinct from logical concurrent scopes = 64;
- obsolete `keys_max_per_namespace=17` removed;
- route and parent import reject reserved/header faults, invalid inner
  records, three images, duplicate generation with different bytes and
  reversed generation order, then retain a permanent mutation fence.

Root independently reran:

```text
generator check/self-test                           PASS (114 cases)
Python independent gate check/self-test             PASS (12,882/12,882 donors rejected)
Node independent gate check/self-test               PASS (12,882/12,882 donors rejected)
```

The implementing reviewer also ran the focused normal and ASan/UBSan RRMP
matrix at 7/7 PASS each. Root will rerun the complete matrix after the
remaining storage-bundle, attempt-ledger and authority-fencing repairs stop
changing production code.
