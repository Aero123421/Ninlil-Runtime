# Unified HIL evidence layer

状態: Informative implementation guide。実機 HIL はこの変更では未実行。

## Purpose and boundary

`tools/ninlil_hil/` は、Ninlil の hardware-in-the-loop 実行を同じ
machine-readable evidence directoryへ集約する、標準 library のみの host
runnerである。対象commandは JSON argv array として実行し、shellを使用しない。
pluginは **operator-trusted local fixture adapter** であり、敵対的な同一OS UIDの
任意コードをportableに隔離するsandboxではない。

このlayerの `PASS` は、manifestに列挙したcaseのlocal plugin observationが閉じた
schemaと一致したことだけを表す。次を意味しない。

- physical power interruptionまたはphysical HIL全体のattestation
- ESP storage `commit(FULL)` の `STORAGE_OK` への昇格
- M3 complete、field readiness、wear acceptance
- release provenance / SBOM attestation

[21章 §7](21-m3-esp-idf-durable-storage.md) と
[Accepted ADR-0006 §6](adr/0006-u6-transport-custody.md) に従い、v1 verdictは
常に `full_promotion_permitted=false`、`runtime_policy=ESP_UNPROVEN`、
`physical_hil_claimed=false` である。local/manual plugin output、changed boot
nonce、relay command success、read-back一致のどれからもFULLへ昇格しない。将来の
昇格には、別のAccepted decision、review済みのattestation authority、source /
firmware / board / flash / fixture identityの検証、release policy変更が必要である。

## Versioned files

schema authorityは `spec/hil/` にある。

| File | Schema | Meaning |
| --- | --- | --- |
| `manifest.json` | `ninlil-hil-manifest-v1` | source、resource declaration、planned case、request |
| `events.json` | `ninlil-hil-events-v1` | pluginから受理したcase observation |
| `resources.json` | `ninlil-hil-resources-v1` | manifest resourceのexact copy。v1は未検証宣言 |
| `faults.json` | `ninlil-hil-faults-v1` | timeout、出力上限、schema、case不一致 |
| `verdict.json` | `ninlil-hil-verdict-v1` | case completenessと非昇格境界 |
| `inventory.json` | `ninlil-hil-inventory-v1` | inventory自身を除く全fileのbyte length + SHA-256 |
| `logs/*.log` | redacted text | bounded stdout / stderr |

`plugin-context.json` はrunnerが生成するcontrol inputであり、schema,
campaign/run/profile、relative `manifest_path="manifest.json"`、canonical plugin name
listを持つ。各pluginは個別のephemeral workspaceで、read-onlyのmanifest/context copy
だけを参照する。最終evidence staging/final directoryのpathはcontextに含めず、plugin
実行中はそのdirectoryを作らない。runnerはcanonical control bytesと捕捉済みの
stdout/stderrだけから、全plugin終了後にfinal evidenceを構築する。control copyの
一時的または終了時の書換えを検出・証明するという主張はしない。

run directoryは `<output-root>/<campaign_id>/<run_id>` で決定的に決まる。同じrun IDの
上書きは拒否する。全plugin終了後にprivate partial directoryで全fileとinventoryを
完成してからrenameする。`verify` はSHA-256だけでなく、
unlisted file、symlink、schema identity、case/fault count、unknown event、FULL promotion
bitの改変も拒否する。

`inventory.json` はinventory自身を除くsealed fileの、strict lexical path順のcanonical JSON
listである。path setは任意ではなく、exactly six core filesと、manifestのplugin name
ごとの`logs/<name>.stdout.log`および`logs/<name>.stderr.log`だけである。許可directoryは
rootと`logs/`だけで、regular file、directory、symlinkを追加したbundleはverifyで拒否
される。同じsealed bytesからは同じinventoryが得られる。一方、別runはrun ID、plugin
observation、log、実行環境に依存するため、異なる実行間のinventory hash一致を再現性の
要件にはしない。再現性の確認は、同じrun directoryを変更せずに`verify`できることと、
全listed fileがexact bytes/hashであることを指す。run commandは
`inventory_receipt_sha256`（`inventory.json` bytesのSHA-256）を出力する。呼出側はこの
receiptをbundle外のimmutableな記録として保持し、`verify --expected-receipt RECEIPT`を
使う。receiptなしのlocal integrity-only verifyはattestationではなく、同一UID者が
post-returnにmanifestとinventoryを再sealしたことを検出できない。

## Plugin protocol

pluginはrepeatable `--plugin-json` objectで渡す。

```json
{
  "name": "storage-S1-delay-013",
  "argv": ["python3", "ports/esp-idf/storage/hil/host_powercut_runner.py", "..."],
  "timeout_seconds": 300,
  "max_output_bytes": 2097152
}
```

`argv` はnon-empty string arrayでなければならない。shell stringは拒否する。
runnerは秘密を含む通常のprocess environmentを引き継がず、`PATH`などの最小集合と
次だけを渡す。

1 campaignは最大32 pluginで、aggregate timeoutは7日、aggregate output ceilingは
64 MiBである。v1 evidenceはcampaign全体で最大4096 event、4096 fault、70 inventory file
（6 core file + pluginごとのstdout/stderr）に閉じる。これらを超える入力または
observationはfail-closedである。inventory path setもこのplugin listから導出され、
plugin workspace内のartifactは最終bundleに入らない。最終bundleのpath setはrunnerだけが
生成し、unplanned pathはverifyで拒否される。

- `NINLIL_HIL_CONTEXT`: read-only plugin context JSON path
- `NINLIL_HIL_PLUGIN`: plugin name

pluginはstdoutにexact prefixと1行JSONを出す。

```text
NINLIL_HIL_EVENT_V1 {"event_id":"run-1","case_id":"HIL-S1-001","outcome":"PASS","observed":{...}}
```

1 caseはexactly 1 eventでなければならない。extra / missing / duplicate event、
unknown case、non-zero exit、timeout、combined output ceiling超過はfail-closed。
secret-like JSON keyはevent自体を拒否する。text logはpassword/token/Bearer/URL
userinfoに加え、`AWS_SECRET_ACCESS_KEY`、`client_secret`、`Cookie`、`credential`
の代表形をpersist前にredactする。argvはevidenceへ保存せず、secretをargvに載せる
運用自体も避ける。

timeoutまたはcombined stdout/stderr上限に達すると、POSIXではbest-effortでpluginの
private process groupをkillする。`start_new_session=True`等で脱出した同一UIDのchildを
portableに停止・隔離できるとは主張しない。そのchildはfinal evidence pathを受け取らず、
最終bundleはplugin終了後にrunnerが生成する。operatorはreceiptをbundle外に保持する。

## Existing atomic storage runner

`host_powercut_runner.py` は `--evidence-case-id` 指定時、既存のstrict result
検査後に統一eventを1件出す。

```sh
python3 ports/esp-idf/storage/hil/host_powercut_runner.py \
  --port /dev/ttyACM0 \
  --scenario S1 \
  --delay-ms 13.5 \
  --prepare-json '["lab-flash","erase-hil-and-reset"]' \
  --power-off-json '["lab-relay","off"]' \
  --power-on-json '["lab-relay","on"]' \
  --evidence-case-id HIL-S1-013
```

emitted observationはscenario、exact event、delay、OLD/NEW、canonical digest、
boot nonce change、power command successを含む。ただし既存fixture interfaceは
flash power railの計測を返さないため
`physical_power_interruption_verified=false`で固定する。

atomic manifestは `create-manifest` で作れる。各`--delay-ms`がD0..D2/S0..S2の
全scenarioへ展開される。

```sh
python3 -m tools.ninlil_hil create-manifest \
  --profile esp-storage-atomic-v1 \
  --campaign-id storage-atomic-20260729 \
  --run-id board01-build0123 \
  --repository-commit FULL_GIT_COMMIT \
  --tree-state clean \
  --firmware-sha256 FIRMWARE_SHA256 \
  --firmware-build-id BUILD_ID \
  --idf-version v5.5.3 \
  --resource-json '{"resource_id":"board","kind":"target_board","identity":"BOARD_ID","verification":"UNVERIFIED_DECLARATION","attributes":{}}' \
  --resource-json '{"resource_id":"fixture","kind":"power_fixture","identity":"FIXTURE_ID","verification":"UNVERIFIED_DECLARATION","attributes":{}}' \
  --delay-ms 0 --delay-ms 1 --delay-ms 2 \
  --output atomic-manifest.json
```

manifestに列挙したdelayが自動的に十分なsweepになるわけではない。
[storage HIL procedure](../ports/esp-idf/storage/hil/run_hil_scenarios.md)どおり、
各eventでOLD側、NEW側、transition周辺の複数attemptをoperatorが計画し、全runを
残す。単一runのPASSをcampaign完了へ読み替えない。

## HIL-NS orchestration

`esp-storage-namespace-v1` profileは、既存仕様の独立した8 phaseをexact orderで要求する。

1. AB: create/verify NS-A → cold reboot/verify → create/verify NS-B → cold reboot/verify
2. fresh erase
3. BA: create/verify NS-B → cold reboot/verify → create/verify NS-A → cold reboot/verify

各eventはcampaign/action、created namespace、boot nonce change、directory
indices、全live namespaceのexact snapshot、unexpected namespace absenceを返す。
runnerは次をcross-eventで検査する。

- namespaceごとのdirectory indexが後続bootでdriftしない
- 同一時点のindexがduplicateしない
- `NS-A={a:A-old,b:A-stable,c:ABSENT}`、`NS-B={a:B-stable,b:ABSENT,c:B-new}`
- each exact `entry_count=2`, `logical_bytes=47`
- cold reboot phaseのboot identity change
- unexpected namespaceがない

manifest生成:

```sh
python3 -m tools.ninlil_hil create-manifest \
  --profile esp-storage-namespace-v1 \
  --campaign-id storage-ns-20260729 \
  --run-id board01-build0123 \
  --repository-commit FULL_GIT_COMMIT \
  --tree-state clean \
  --firmware-sha256 FIRMWARE_SHA256 \
  --firmware-build-id BUILD_ID \
  --idf-version v5.5.3 \
  --resource-json '{"resource_id":"board","kind":"target_board","identity":"BOARD_ID","verification":"UNVERIFIED_DECLARATION","attributes":{}}' \
  --resource-json '{"resource_id":"fixture","kind":"power_fixture","identity":"FIXTURE_ID","verification":"UNVERIFIED_DECLARATION","attributes":{}}' \
  --output namespace-manifest.json
```

現行 `hil_app` はHIL-NS用のprivate directory index protocolを提供しない。このため
本変更が実装するのはmanifest/event/cross-phase orchestrationまでで、実行には
directory indexを報告できる専用fixture pluginが必要である。atomic power-cut
runner、host model、manual transcriptionをHIL-NS eventに代用してはならない。

## Run, verify, and CI-safe self-test

```sh
python3 -m tools.ninlil_hil validate-manifest --manifest manifest.json

python3 -m tools.ninlil_hil run \
  --manifest manifest.json \
  --output-root hil-runs \
  --plugin-json '{"name":"case-1","argv":["fixture-plugin","--case","case-1"]}'

python3 -m tools.ninlil_hil verify \
  --run-dir hil-runs/CAMPAIGN_ID/RUN_ID
```

## Exit status

CLIはexit statusをCIの判定に使えるよう固定する。

- `run`: sealed verdictが`PASS`なら0、`FAIL`なら2。manifest、plugin、filesystemの
  errorも2。
- `verify`: integrityとsemantic verificationが通り、verdictが`PASS`なら0。verified
  `FAIL` bundleも通常は2である。故障解析でFAIL bundleのhash/formatだけを確認したい
  場合だけ、明示的に`verify --allow-failed`を使う。この場合も改ざん・schema不一致は2。
- `validate-manifest`、`create-manifest`、`self-test`: 成功時0、入力または検証失敗時2。

`--allow-failed` はPASSへの昇格でもacceptanceでもない。operatorが既知のFAIL evidenceを
読み出すための限定したintegrity-only exit policyである。

offline self-testはhardware、network、pyserial、third-party packageを必要としない。
positive run、argv execution、control-file mutation、plugin-created regular file/directory/
symlinkによるseal中止、timeout/output-limit時のdescendant kill、redaction、SHA-256
inventory、re-hashed unknown event、FULL bit mutation、extra file、duplicate case、path
traversal、shell string、secret event、bool/int混同、HIL-NSのreverse order/index driftを
検査する。各positive/negative runで生成されるmanifest、events、
resources、faults、verdict、inventoryは、checked-in draft-2020-12 schema instanceとしても
検査する。CIから実行してもphysical HIL PASSを生成しない。

```sh
python3 -m tools.ninlil_hil self-test
python3 ports/esp-idf/storage/hil/host_powercut_runner.py --self-test
```
