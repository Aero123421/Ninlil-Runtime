# 2026-07-29 Wi-Fi / Fabric durable 10k close

状態: **Host software path and ESP32-S3 final-ELF/map verified; physical
ESP/AP HIL remains NOT_RUN**

本記録は非規範である。Normative statusは
[ADR-0017](../adr/0017-bearer-registry-path-selection.md) と
[ADR-0018](../adr/0018-wifi-bearer.md) に従い、ADR-0018は引き続き
`Proposed`、`SPEC_ACCEPTED` / `RELEASE_SUPPORTED`ではない。

## Closed software defects

- Wi-Fi packet-linkの有限Permit ledgerを、Fabricのdurable FBA1へ
  co-locateしたone-shot Permit authorityで包んだ。別のPermit recordは
  存在しない。provider ledgerはterminal release後に再利用できるが、同じ
  `(permit clock epoch, Permit ID)`はlive時、release後、
  process crash/reopen後のすべてでTX 0 / `DENIED`となる。
- FBA1のPermit claimはprovider `start_send`より前に、同じFBA1の
  `CLEAR -> CLAIMED` `FULL` replacementとして確定する。definite
  non-acceptはattempt state更新とclaim clearを同じFBA1 `FULL`へまとめる。
  RETAINEDまたはuncertain outcomeは`CLAIMED`を維持し、同じpairの再発行を
  禁止する。これにより、Permit claimとattempt stateを別recordへ分けた時に
  生じるatomicity gapを除去した。
- retention完了済み`DRAINED` FBA1はdurable recordを保持したまま
  bounded RAM attempt slotから回収する。同じattempt identityの再利用は
  durable prefix lookupで`CORRUPT`となり、10,000件でRAM上限を越えても
  oldest active/unknown recordをevictしない。
- terminal `dispatch_release`はprovider tokenに加えvolatile packet slotも
  exact 1回解放する。
- process reopen時のpath-selection epochはdurable maxの次値から再開し、
  wrapはfail-closedとする。
- journal / credential / M4 durability pathは`COMMIT_UNKNOWN`を専用statusで
  callerへ残し、uncertain write後のI/O再開を禁止する。

## Real Host acceptance path

`tools/wifi_v1_run_host_e2e.sh`の先頭scenarioは、次の実経路を通る。

```text
Fabric outer bearer send
  -> FBA1 PREPARED FULL
  -> same FBA1 permit CLEAR -> CLAIMED FULL
  -> Wi-Fi packet-link start_send
  -> NWB1
  -> TLS 1.3 / TCP loopback
  -> peer response (NWB1 / TLS)
  -> ordered ingress transcript
  -> Fabric terminal + dispatch_release
```

各requestについてpeerがminimum-valid NFL1 responseをexact 1件返す。
clientは次requestへ進む前に、NWB1 sequence、accepted件数、NFL1 length、
full NFL1 SHA-256を照合する。duplicate、gap、reorder、別payloadは失敗である。
frame 5,000でPOSIX SQLite storage leaseをcrash扱いにして破棄し、同じDBを
reopenする。graceful Fabric closeをcrashの代用にはしていない。

成功時のexact tokenは次である。

```text
Fabric start_send/TLS completion/release frames=10000 responses=10000 exactly-once replay-denied=live+restart
```

## Local evidence

### Normal / sanitizer

```text
normal Wi-Fi/Fabric CTest:      39/39 PASS
ASan/UBSan Wi-Fi/Fabric CTest: 39/39 PASS
```

この39件にはactual adapter → real Fabric、Host socket/TLS E2E、
FBA1 codec/lifecycle/CU/GC/cold-reopen、private archive symbol boundaryを
含む。direct raw packet-linkはTX 0 / `DENIED`で、登録前、wrong Fabric、
unregister後のstale authorityもTX 0 / `DENIED`となる。

`fabric_v1_lifecycle`はsame-FBA1 claim/clearの
`OLD / NEW / PARTIAL / THIRD` CU分類、provider RETAINED後のuncertain
state、64/65 capacity、Permit expiry/epoch、cold reopen、bounded GCを検査する。
runtime release済みDRAINED FBA1もGCがphysical eraseするまではpolicy /
authority removalをblockする。

### Pinned OpenSSL 3.5.7 Host authority / 10,000件

公式`openssl-3.5.7.tar.gz`をSHA-256
`a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8`
で検証し、`no-shared no-tests no-module no-legacy`でstatic buildした。
provenance gateはexact tag/peeled commit、CMake cache、final link command、
retained static symbol、isolated `OSSL_LIB_CTX`、final binary dependencyを検査し、
次を返した。

```text
authority_claim_allowed=true
provenance_status=OK
dynamic libssl/libcrypto dependencies=0
runtime=OpenSSL 3.5.7 9 Jun 2026
```

同じauthority binaryの保存ログで次をexactに確認した。

```text
server received frames=10000 ordered
server Fabric responses=10000
client sent frames=10000
Fabric start_send/TLS completion/release frames=10000 responses=10000 exactly-once replay-denied=live+restart
```

その後、malformed、expired/wrong leaf profile、bidirectional、slow reader、
exporter、credential revoke/rotate、AP disconnect、restart-midstream、
journal recovery、blackholeの全scenarioも`ALL PASS`となった。

### Completion integrated E2E

`tools/host_completion_integrated_e2e.sh`を直接実行し、Wi-Fi + Fabric +
RRMP + MFDTの統合経路をstrict buildとASan/UBSan buildの両方で完走した。

```text
scenario strict: PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
scenario asan:   PASS digest=6823a37fad944dd1947d0ad148bf91fc41e90acc8641791c7780d9cdd6c4951e
host_completion_integrated_e2e: ALL PASS
```

統合gateを実経路に合わせて次のとおり修正した。

- direct strict source listへ`wifi_storage_cu.c`を追加し、Wi-Fi durable
  storage read/CU symbolを実体付きでlinkする。
- RRMP link ACK evidenceのpeer runtime IDを、installed routeのexact
  egress peerへ一致させる。異なるpeerによるACKを許容してはいない。
- publication logからdigest 64桁と`durable_pub=1`をexactに抽出・検査する。
- endpoint cold restartでは、内部self-pointerを持つlab storeを
  shallow-copyしない。file export/import後の独立store/engine/workspace/
  pipelineを関数終了まで生存させ、その復元imageへ切り替える。
  ASanの`stack-use-after-scope`を抑制せず解消した。

### CI load allocation

標準CTest `wifi_v1_host_e2e`はtest propertyで`FRAMES=200`へ固定し、
normal/ASanなど通常matrixでは同一経路のbounded regressionを行う。
full 10,000件証拠は削除せず、pinned OpenSSL authority jobだけが登録CTestを
excludeしたうえで、`FRAMES=10000 tools/wifi_v1_run_host_e2e.sh ...`を
明示実行する。これにより、release evidenceの強度を変えずに通常CIで
約18分のSQLite full-image負荷を重複実行しない。

## Performance observation

FBA1は最大64 active attemptだけをRAMへ保持し、DRAINED historyは
bounded GCで1 erase / 1 work itemとして回収する。今回のpinned Host
10,000往復のhappy pathは約10秒、全negative/recovery scenarioを含むrunnerは
約16秒で完了した。この観測値はmacOS loopbackであり、radio/AP throughputや
field latencyの主張ではない。

## ESP32-S3 final-ELF/map and package boundary

固定ESP-IDF v5.5.3 arm64 image
`sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1`
でfresh buildし、final ELF/map/resource gateを完走した。

```text
wifi_v1_esp_resource_gate PASS
ESP production archive members present=26
Host-only members present=0
owner workspace=9008 <= 12288 bytes
stack-usage entries=350, each <=8192 bytes
DIRAM=169935 / 341760 bytes
static HIL workspaces in internal BSS=41088 bytes
mbedtls_ssl_export_keying_material retained
physical_ap_hil=NOT_RUN
```

PSRAMは`CONFIG_SPIRAM_USE_CAPS_ALLOC=y`でexplicit allocationだけを許し、
external BSSとdefault malloc spillは無効である。Wi-Fi TLSのsole allocatorは
`MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT`を要求するため、このimageのWi-Fi
workspace/TLS allocationをPSRAMへ暗黙退避しない。runtime peak/watermarkは
物理HILで未測定であり、map proofから捏造しない。

このcomposition PASSをADR-0018 C7/C8 resource completionへ昇格しては
ならない。link-time DIRAM残量`171825` bytesに対し、Normative ceilingを
同時reserveするならTLS session pool `196608` + crypto global `65536` +
post-admission free `65536` = `327680` bytesが必要で、internal-only allocator
では算術上成立しない。現実装も`SESSION_POOL_BUDGET`、
`CRYPTO_GLOBAL_BUDGET`、`MIN_FREE_INTERNAL_HEAP`をadmissionへ適用せず、
session owner 2枠だけでglobal/prewarm accountingを実装していない。
したがってresource release statusは**NO-GO**である。解決には実機raw
allocator traceに基づくNormative budget再審査、またはPSRAM tieringの
Normative amendmentと実装・独立reviewが必要である。

Host tests-OFFでfeature OFF / ONを別々にbuild/installし、OFF archiveの
Wi-Fi/Fabric symbol 0、ON private archivesの実symbol、両install prefixの
private path/header/symbol 0を確認した。Wi-Fi/Fabricは引き続き
private、default-OFF、non-installedである。

## Non-claims

- ESP32-S3 final ELF/mapは検証したが、実機、実AP/DHCP、WPA2/WPA3、
  sleep/wake、physical HILは実行していない。
- 1-hour session、24h soak、bulk/critical fairness、全resource ceilingを
  この10,000件だけで完了扱いにしない。
- system OpenSSL 3.6.3 LAB runをpinned OpenSSL 3.5.7 authorityと主張しない。
- TLS socket write完了またはpeer responseをcustody / Application Receiptへ
  昇格しない。
