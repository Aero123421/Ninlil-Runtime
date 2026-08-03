# OSS package worktree completion follow-up

Date: 2026-07-30

## Scope

This record closes the local worktree implementation and verification lane for:

- Apache-2.0 / NOTICE / third-party notice consistency;
- dependency inventory and SPDX generation;
- deterministic source archives;
- Linux/macOS release workflow structure;
- tests-OFF install/package and external-consumer boundaries;
- ESP-IDF public/private include separation.

It does not promote the release state. The current worktree is not yet an
immutable release commit, remote GitHub Actions have not run for that future
commit, and physical HIL remains `NOT_RUN`.

## Defects closed

### RRMP HIL evidence schema drift

The checked-in RRMP physical-HIL template carried the accepted-spec/private
candidate prerequisites and executable-tool provenance, while its closed JSON
Schema omitted those fields. A source archive therefore passed payload
validation but failed its own clean-room HIL self-test.

The schema now requires:

- `software_prerequisites.spec_accepted`;
- `software_prerequisites.private_implementation_candidate`;
- the three bounded `tooling` provenance fields.

The HIL self-test has missing-field and unexpected-field negative cases. The
template still reports `status=NOT_RUN`; no hardware claim was promoted.

### Private ESP target-smoke headers on a public include path

MFDT and RRMP target-smoke declarations were under
`ports/esp-idf/include/ninlil_esp_idf/`, which is an ESP-IDF public
`INCLUDE_DIRS` root. They are private test/application contracts, not SDK
headers.

Both headers now live under `ports/esp-idf/src/`, already consumed only through
`PRIV_INCLUDE_DIRS`. The general ESP public-boundary gate also rejects any
future `*target_smoke*.h` header under a public include root.

## Local verification

| Gate | Result |
| --- | --- |
| `release_forbidden_vocabulary_gate.py check` | PASS; zero forbidden product vocabulary |
| `markdown_link_gate.py check` | PASS |
| `compatibility_matrix_gate.py check/self-test` | PASS |
| `third_party_notice_gate.py check/self-test` | PASS |
| `release_version_identity.py self-test` | PASS; core `0.1.0` |
| `release_workflow_identity_gate.py check/self-test` | PASS |
| actionlint 1.7.12 + ShellCheck 0.11.0 over every workflow | PASS |
| pinned Syft 1.49.0 actual scan, SPDX enrich/check | PASS |
| two independent Syft scans after canonical enrichment | byte-identical |
| source tar/zip two-run, canonical metadata and full payload equivalence | PASS |
| supplied-worktree-archive clean-room | PASS |
| clean-room HIL evidence self-tests | PASS; not `HIL_VERIFIED` |
| clean-room tests-OFF install and independent consumer lifecycle | PASS |
| fresh macOS package/version/install consumers | 6/6 PASS |
| ESP-IDF component packaging/public-boundary self-tests | PASS |
| MFDT Host/ESP/install boundary | PASS; zero MFDT symbols in public archive |
| staged and unstaged `git diff --check` | PASS |

The package clean-room exercised tests-ON public smoke, Markdown links,
traceability, tests-OFF build/install, and an independent installed consumer.
The direct install inventory contained only public headers, CMake metadata,
public archives, legal notices, and the machine-readable compatibility and
dependency inventories.

## Remaining release gates

The ordered distribution authority intentionally remains red at its
commit-tree step while the implementation is a dirty worktree: the old `HEAD`
contains the previous NOTICE bytes and cannot represent this candidate.

After integration, the release steward must:

1. fix the complete candidate as one reviewed commit and verify a clean
   worktree;
2. rerun `release_distribution_authority_gate.py check` and the
   `build-from-git --two-run --source git` archive path on that exact commit;
3. push the same SHA and require Linux, macOS, sanitizer, ESP32-S3, and release
   dry-run workflows to pass;
4. download and independently verify the five dry-run assets;
5. keep physical USB, RF, real-AP, flash power-cut, failover, and soak evidence
   at `NOT_RUN` until their hardware campaigns actually run.

Local worktree success is not `RELEASE_SUPPORTED`, remote-CI evidence, legal
certification, or physical-HIL evidence.
