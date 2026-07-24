# V1 LAB leak example fix evidence (2026-07-24)

## A. Exit codes (4 examples)

### Before fix

```
$ cd tmp-v1
$ for e in ninlil_v1_lab_controller_submit_example ninlil_v1_lab_cell_custody_example ninlil_v1_lab_display_latest_state_example ninlil_v1_lab_leak_measurement_example; do ./$e; echo rc=$?; done
v1_lab_controller_submit ok
rc=0
v1_lab_cell_custody ok
rc=0
v1_lab_display_latest_state ok
rc=0
v1_lab_leak_measurement failed
rc=1
```

### After fix

```
$ cd tmp-v1
$ for e in ninlil_v1_lab_controller_submit_example ninlil_v1_lab_cell_custody_example ninlil_v1_lab_display_latest_state_example ninlil_v1_lab_leak_measurement_example; do ./$e; echo rc=$?; done
v1_lab_controller_submit ok
rc=0
v1_lab_cell_custody ok
rc=0
v1_lab_display_latest_state ok
rc=0
v1_lab_leak_measurement ok
rc=0
```

## B. Root cause

MeasurementBatch uplink (`NINLIL_FAMILY_MEASUREMENT_RESERVED`, service `leak-measurement`) は POSIX LAB の canonical origin authorization で `latest_state_lab_allow`（`latest-state` 専用）にも `source_and_service_match`（`EVENT_FACT` / `durable-event` 専用）にも該当せず、`fixture_evaluate` が `NINLIL_REASON_GRANT_INVALID` で deny する。endpoint child は `ninlil_submit` が `NINLIL_SUBMISSION_REJECTED`（kind=3）となり admission 前に失敗するため、runtime step で bearer egress（`inject_send_count`）に到達しない。LatestState（display）は `latest_state_lab_allow` があるため同一 harness で通過する。`test_measurement_batch_retention` は family workspace 単体のため origin auth を経由せず PASS のまま。

## C. CTest

```
$ ctest -R 'v1_lab_.*_example' --test-dir tmp-v1
4/4 Passed

$ ctest -R 'measurement|family' --test-dir tmp-v1
2/2 Passed (v1_runtime_family, v1_lab_leak_measurement_example)

$ ctest -R canonical_origin_authorization_fixture --test-dir tmp-v1
1/1 Passed
```

## D. Full subset (v1_ / family / e2e)

```
$ ctest -R 'v1_|family|e2e' --test-dir tmp-v1
22/22 Passed
```

## Change

`tests/support/canonical_origin_authorization.c`: `measurement_batch_lab_allow` を `latest_state_lab_allow` と同型で追加（`leak-measurement` service/schema、`NINLIL_EVIDENCE_APPLIED`、generation 系 event_id=0）。

RC=0
