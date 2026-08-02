# NTS3 schema 1.2 MFDT target correlation

Date: 2026-08-02  
Status: **3B codec/internal correlation implemented; 3C admission ordering remains blocked**

## Scope

ADR-0021の「Foundation NTS3 correlation amendment」だけをproduction codecと
private Runtime内部に反映した。公開API、新しいtable/state/migration、
carrier/pre-arm/handoffのorderingは追加しない。

## Implemented boundary

- private `ninlil_rt_target_slot_t`に`mfdt_transfer_id[16]`と
  `mfdt_target_ordinal`だけを追加した。
- NTS3 writer/readerをschema minor 1.2へ進めた。MFDT routeだけが
  各canonical target末尾に16-byte transfer ID + u32 BE ordinalを持つ。
- sender originは1..4 targets、non-zero ID、ordinal == canonical index。
  receiver originは1 target、non-zero ID、ordinal 0..3。Non-MFDTは
  suffix不在かつin-memory zero/zeroに固定した。
- 1.0/1.1/unknown minorはimplicit migrationせず`NINLIL_E_UNSUPPORTED`で
  fail closedする。Domain Storeの別schemaは変更していない。
- encodeはcount-only passでrequired lengthを先に決め、capacity不足時は
  `out_length=0`とoutput bytes不変を保証する。
- transfer ID導出をprivate Runtime ownerの1 helperへ集約した。
  Foundation admission candidateはNTS3 encodeより前にcanonical targetごとに
  ID/ordinalを保持し、sender sidecar openにはその同じID bytesを渡す。
  独立のtest derivationとproduction helperのbyte-exact一致も検査した。

## Exact codec acceptance

- MFDT 4-target worst case: **3,185 bytes** round-trip。
- MFDT capacity 3,184: `NINLIL_E_BUFFER_TOO_SMALL`、`out_length=0`、
  output canary不変。
- target末尾suffixの位置/順序、ID、u32 BE ordinalをbyte単位で検査。
- sender ordinal mismatch / zero IDはencode reject、CRCを修復した同変異も
  decode時にstorage corruption。
- receiver ordinal 3をround-tripし、4はreject。
- non-MFDT worst case: **4,031 bytes**、suffixなし、decode後zero/zero。
  non-zero correlation入力はencode reject。
- schema 1.1とunknown minorをdecode/envelope validationの両方でreject。

## Verification

Normal build:

```text
ctest -R 'mfdt|multi_frame'                                      41/41 PASS
Foundation codec/durable/restart focused set                     9/9 PASS
host_runtime_tests_off_installed_consumer + install boundary     2/2 PASS
```

ASan/UBSan build:

```text
ctest -R 'mfdt|multi_frame'                                      41/41 PASS
Foundation codec/durable/restart focused set                     9/9 PASS
```

Feature-OFF (`NINLIL_BUILD_TESTS=OFF`, `NINLIL_ENABLE_MFDT_V1_PRIVATE=OFF`)
build/installも成功し、installed runtime archiveのMFDT symbolは0、installed
public header/CMakeのMFDT private名も0である。

Focused Foundation setは`runtime_store_codec`, `v1_durable_allowlist`,
`v1_transaction_codec`, `v1_event_mgmt_ledger`, `v1_runtime_spine`,
`v1_runtime_delivery`, `v1_runtime_family`, `v1_posix_sqlite_restart_e2e`,
`v1_posix_platform_restart_e2e`。

## Baseline-equal failures / 3C blocker

`v1_runtime_capability` full executableは3A直前と3B後のstdout/stderrが
byte-for-byte同一、exit 1のままである。失敗は次の4箇所。

```text
v1_runtime_capability_test.c:1071  payload 927 submit status=1
v1_runtime_capability_test.c:1397  payload 927 submit status=1
v1_runtime_capability_test.c:1478  payload 927 submit status=1
v1_runtime_capability_test.c:1598  expected NINLIL_E_STORAGE mismatch
```

最初の3件の根因は、current admissionがsender sidecar OPENを作る時点で
`original_attempt_id` がall-zeroなことである。OPEN validatorは正しく
`MFDT_ERR_LAYOUT (-7)`で拒否する。ADR-0021が求めるtargetごとの
attempt candidate選択、sidecar pre-arm、Foundation同一FULLのorderingは3Cである。
3Bでtransfer IDをattempt IDに流用せず、失敗をGREENとして隠さない。

`runtime_lifecycle_model` line 1098の1 failureも3A直前/3B後でoutputと
exit statusが同一で、3Bとは無関係な共有worktree baseline failureである。

## Reproduction

```sh
cmake --build build-codex-mfdt-sentinel-fresh-normal-20260802 -j 8
ctest --test-dir build-codex-mfdt-sentinel-fresh-normal-20260802 \
  --output-on-failure -R 'mfdt|multi_frame'
ctest --test-dir build-codex-mfdt-sentinel-fresh-normal-20260802 \
  --output-on-failure \
  -R '^(runtime_store_codec|v1_durable_allowlist|v1_transaction_codec|v1_event_mgmt_ledger|v1_runtime_spine|v1_runtime_delivery|v1_runtime_family|v1_posix_sqlite_restart_e2e|v1_posix_platform_restart_e2e)$'

cmake --build build-codex-mfdt-sentinel-fresh-asan-20260802 -j 8
ctest --test-dir build-codex-mfdt-sentinel-fresh-asan-20260802 \
  --output-on-failure -R 'mfdt|multi_frame'

cmake --build build-codex-mfdt-sentinel-fresh-off-20260802 -j 8
cmake --install build-codex-mfdt-sentinel-fresh-off-20260802 \
  --prefix /tmp/ninlil-3b-off-install
```

## Nonclaims

3Bは3C admission ordering/reconciliation、Application handoff/Receipt、公開MFDT API、
default-ON、ESP実機/HIL、release supportの完成を主張しない。
