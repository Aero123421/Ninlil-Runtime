# OSS release surface verification (root rerun)

Date: 2026-07-29

## Scope

This rerun verifies the current worktree's public OSS and release surface while
feature implementation continues. It does not promote any radio, Wi-Fi, ESP,
or physical-HIL state.

## Results

The following checks passed against the worktree:

- `python3 tools/compatibility_matrix_gate.py check`
- `python3 tools/markdown_link_gate.py check`
- `python3 tools/release_forbidden_vocabulary_gate.py check`
- `python3 tools/release_workflow_identity_gate.py check`
- `python3 tools/third_party_notice_gate.py check`
- `python3 tools/release_version_identity.py self-test`
- `python3 tools/spdx_release_sbom.py self-test`
- `python3 tools/release_archive_payload_gate.py self-test`
- PyYAML parse of all three files under `.github/workflows/`
- actionlint 1.7.12 with ShellCheck against all three workflow files
- `git diff --check` and `git diff --cached --check`

The forbidden-vocabulary gate inspected 782 tracked text files and reported
zero hits. The release archive self-test exercised fail-closed mutations and
then produced two reproducible worktree archives with equivalent tar/zip
payloads. The archive included 1,197 files at this snapshot.

## Deferred checks

The commit-tree release dry run is intentionally deferred until the complete
worktree has been reviewed and committed; validating the old `HEAD` would not
validate the current implementation. Full normal, sanitizer, ESP-IDF, and
clean-room matrices are rerun after the in-progress R7 and Wi-Fi/Fabric changes
stabilize.

Physical USB, SX1262 RF, real-AP, flash power-cut, multi-device failover, and
soak evidence remain `NOT_RUN`.
