# Ninlil Host Runtime SDK

状態: 現行 `main` の installable Host SDK 利用ガイド

この文書は、履歴リリース `v1.0-lab-rc2` ではなく、現行source treeから
installする Host Runtime SDK を説明します。CMake packageとしての生成・利用は
検証済みですが、物理USB/RF、Wi-Fi、relay、multi-parent、完全fragmentation、
production法規適合まで完成したという主張ではありません。

ADR-0029のfirst trancheとして、portable transport composition boundary
`fabric_v1`もexperimental public SDKとしてinstallできます。Application APIの
正本は引き続きFoundation Runtimeであり、ApplicationがFabricのcodec、route、
fragmentやstorage recordを直接操作する設計ではありません。

## 1. Support boundary

| 項目 | 現行要件 |
| --- | --- |
| Host OS | Linux / macOS |
| Repository build / CTest | CMake 3.20以上 |
| Installed package consumer | CMake 3.20以上 |
| C / C++ header smoke | C11 / C++17 |
| Host Runtime crypto | OpenSSL 3.x `Crypto`（major versionをexactに検査） |
| POSIX durable storage | SQLite3（任意） |

ESP-IDF componentは別のtarget buildです。このHost SDKのsupport boundaryを、
ESP32-S3実機HILやproduction field supportへ読み替えません。

## 2. Build and install

SQLiteに依存しないHost Runtime package:

```bash
cmake -S . -B build-sdk -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DNINLIL_BUILD_TESTS=OFF \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_FABRIC_V1=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=OFF
cmake --build build-sdk --parallel
cmake --install build-sdk --prefix /path/to/ninlil-prefix
```

POSIX SQLite providerも生成する場合:

```bash
cmake -S . -B build-sdk-sqlite -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DNINLIL_BUILD_TESTS=OFF \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
cmake --build build-sdk-sqlite --parallel
cmake --install build-sdk-sqlite --prefix /path/to/ninlil-prefix
```

`NINLIL_BUILD_POSIX_SQLITE_STORAGE=ON` はSQLite3を探索します。SQLite targetを
必須とする配布では、configure logに
`POSIX SQLite storage port: enabled` があることを確認してください。

主なbuild option:

| Option | top-level既定 | `add_subdirectory`既定 | 意味 |
| --- | --- | --- | --- |
| `NINLIL_BUILD_TESTS` | ON | OFF | CTest、examples、private verification targets |
| `NINLIL_ENABLE_STRICT_WARNINGS` | ON | OFF | 対応compilerでwarningをerror化 |
| `NINLIL_BUILD_HOST_RUNTIME` | ON | OFF | `Ninlil::runtime`をbuild / install |
| `NINLIL_BUILD_FABRIC_V1` | Host Runtimeと同値 | Host Runtimeと同値 | experimental `Ninlil::fabric_v1`をbuild / install |
| `NINLIL_BUILD_POSIX_SQLITE_STORAGE` | ON | ON | 発見時にPOSIX SQLite providerをbuild / install |
| `NINLIL_ENABLE_SANITIZERS` | OFF | OFF | Host ASan / UBSan verification build |
| `NINLIL_ENABLE_POINTER_COMPARE_SANITIZER` | OFF | OFF | 対応HostでASan pointer-compare専用gate |

`add_subdirectory` consumerはtests、strict warning、Host Runtimeを暗黙に有効化
しません。必要なtargetだけを明示的にONにしてください。SQLite optionは両方で
ONですが、SQLite3が見つからなければprovider targetは生成されません。

Install treeには`${CMAKE_INSTALL_DATADIR}/ninlil/compatibility-matrix.json`も含まれます。
Release/commitの対応platform、feature状態、HIL境界はこのmachine-readable matrixを参照し、
READMEの概算やbinaryの存在からsupportを推測しないでください。Source treeでは次で
CMake/ABI/storage/ESP-IDF/CI/evidenceとの一致を検証できます。

```bash
python3 tools/compatibility_matrix_gate.py check
```

## 3. Installed consumer

最小のconsumer CMake:

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_ninlil_host LANGUAGES C)

find_package(Ninlil CONFIG REQUIRED)

add_executable(my_ninlil_host main.c)
target_link_libraries(my_ninlil_host PRIVATE Ninlil::runtime)
```

configure:

```bash
cmake -S . -B build \
  -DCMAKE_PREFIX_PATH=/path/to/ninlil-prefix
cmake --build build --parallel
```

`Ninlil::runtime` は `ninlil_platform_ops_t` を通じてallocator、clock、entropy、
storage、bearer等を受け取ります。SQLiteを使わないconsumerは、公開
`ninlil_storage_ops_t` ABIを満たす独自providerを渡せます。SQLite付きpackage
では、次のtargetも利用できます。

```cmake
target_link_libraries(my_ninlil_host PRIVATE
    Ninlil::runtime
    Ninlil::ninlil_posix_sqlite_storage
)
```

Runtimeへ複数のpacket-linkを合成する場合は、public
`#include <ninlil/fabric_v1.h>`だけを使い、Fabricから取得した単一の
`ninlil_bearer_ops_t`をRuntime platformへ設定します。

```cmake
target_link_libraries(my_ninlil_host PRIVATE
    Ninlil::runtime
    Ninlil::fabric_v1
)
```

profile 1はcaller-ownedで`NINLIL_FABRIC_WORKSPACE_BYTES`（現在198656 bytes）の
workspaceを必要とします。必要量とalignmentのauthorityは
`ninlil_fabric_v1_workspace_required()`です。1 instanceは最大16 links、64
policies、64 authority bindings、64 active attempts、1 policyあたり8 candidates
です。instance、workspace、platform vtable user、packet-link provider userの寿命を
public headerとADR-0029どおりに保ち、owner contextからbounded `step`を駆動して
closeを完了させてください。

Packet-link provider実装チェックリスト:

- provider callbackはFabricのowner contextで同期実行される。callback中にFabric、
  Runtime、同じprovider vtableへ再入しない。
- `start_send`中だけborrowされるpacket/Permitを保存しない。RFはPermitを必須とし、
  providerでも`NINLIL_ABI_VERSION`/exact size、non-zero permit ID、packet attempt一致、
  `NINLIL_PORT_OK`＋`NINLIL_CLOCK_TRUSTED`のmonotonic Clock、clock epoch一致、
  `now_ms < expires_at_ms`（expiryはnon-zero）を検証する。成功consume済みの
  `(clock_epoch_id, permit_id)`は再利用を拒否する。
- `RETAINED`前にpacketとretry状態をbounded storageへcopy-ownする。Fabricからのpollは
  stepごとに最大1回、deadlineでのcancelはexactly onceとし、terminal後はどちらも再実行しない。
  `poll_send`は`NINLIL_FABRIC_LINK_OK`＋closed completion kindだけ、`cancel_send`は
  `NINLIL_FABRIC_LINK_OK`または`NINLIL_FABRIC_LINK_LOST_UNKNOWN`だけを返す。
  retained tokenは`release_send` exactly onceまで有効に保つ。
- receive bytesは`release_received`までprovider所有とし、成功loanごとexactly once
  releaseする。`user`、handle、token、workspace、registrationの寿命をpublic headerどおりに保つ。
- shutdownは`close_begin`後もbounded `step`でdrainし、`close_poll(done=1)`より前に
  provider資源やworkspaceを破棄しない。成功openごとのhandleをloan/token drain後に
  exactly once closeし、成功した`destroy`後だけworkspaceを再利用する。

## 4. Exported targets and dependencies

| Target | 条件 | 内容 |
| --- | --- | --- |
| `Ninlil::ninlil` | 常時 | Public header用INTERFACE target |
| `Ninlil::runtime` | Host Runtime有効時 | Public Host Runtime static archive |
| `Ninlil::fabric_v1` | Fabric v1有効時 | Portable experimental Fabric static archive |
| `Ninlil::ninlil_posix_sqlite_storage` | SQLite provider生成時 | POSIX SQLite storage static archive |

現行 `Ninlil::runtime` は単一static archiveであり、OpenSSL 3
`OpenSSL::Crypto` はtarget全体の推移依存です。OpenSSL不要部分を別targetへ
分割することは将来のpackage granularity設計であり、現行packageの保証では
ありません。OpenSSLやSQLite本体はNinlilのinstall treeへ同梱しません。

Runtime archiveのsource authorityには、host simulationで利用する一部の
C4/C5/C6内部software-path実装も含まれます。ただし、C4/C5/C6を独立した
public module、物理USB/RF実装、またはproduction-ready bearerとしてexportする
ものではありません。個別private target / headerは非exportで、物理HILも未完了
です。

## 5. Package verification

`NINLIL_BUILD_TESTS=ON`かつHost Runtime有効時、次を登録します。

| CTest | 検証 |
| --- | --- |
| `host_runtime_tests_off_installed_consumer` | SQLite OFF、tests OFF install、public APIだけのmemory storageで4 Service、durable submit/dedupe/conflict、query/list、capacity/metrics、step、同じprovider objectを使ったRuntime cold restart |
| `host_runtime_tests_off_installed_consumer_sqlite` | SQLite ON時、上記に加えてinstalled SQLite provider自体をdestroy/recreateし、同じdisk DBからservice/transaction/dedupeを復元 |
| `host_runtime_tests_off_installed_consumer_domain_on` | Domain Schema 1を含むinstalled archiveのsymbol surfaceと、未公開profileのRuntime createが`NINLIL_E_UNSUPPORTED`でfail closedすること |
| `fabric_v1_tests_off_installed_consumer` | tests-OFF clean install、public header/target purity、独立した2組のRuntime/Fabricによるsubmit→peer callback→reverse Receipt |
| `fabric_v1_public_api` | exact 19-function wrapper linkage、closed status/bounds、workspace resultのone-to-one mapping |
| `fabric_v1_public_behavior` | public wrapperでwrong-thread/re-entryのzero-effectとbounded close後のno-provider-callback |
| `posix_sqlite_storage_installed_consumer` | POSIX providerのinstall surface、path hygiene、external consumer matrix |
| `runtime_private_subproject_smoke` | `add_subdirectory`時のpublic/private target境界 |
| release archive clean-room | sealed archiveからtests-OFF install後、同じ4 Service durable/restart consumerを独立configure/build/run |

4 Service consumerは1つのEndpoint Runtimeへ同時に次を登録します。

- `display.command`: DesiredStateの受信
- `temperature.query`: DesiredStateの問い合わせ受信
- `access.event`: EventFactの送信
- `temperature.telemetry`: 定期値と問い合わせ応答EventFactの送信

これは特定アプリケーションの語彙をCoreへ追加するものではありません。service IDと
binary payloadはconsumer側のApplicationDataです。公開M1a contractに従い、
問い合わせはDesiredState、応答はEventFactとして相関させます。

consumerは出力markerだけでは合格しません。各service handle、transaction ID、
canonical digest、record revision、list件数、capacity、metricsをassertします。同じ
idempotency keyとdigestは同じtransaction IDを返し、異なるdigestはconflictとなり、
いずれも新しいtransactionやrecord revisionを作らないことを再起動前後で確認します。
service registryの復元は、fresh Runtimeが同一key/revisionの異なるdescriptor contractを
4件とも`NINLIL_E_CONFLICT`で拒否し、その後に元のdescriptorを再attachできることで確認します。
compile graphはinstalled `Ninlil::runtime`と、SQLite ON時だけinstalled
`Ninlil::ninlil_posix_sqlite_storage`を使い、source-tree/private/test/example helperの
include・linkを拒否します。主要API、restart/reopen、assertを除去したsource mutationも
gate自身が拒否します。

SERVICE registryの初回登録とSERVICE capacityの`used/high_water`は同じFULL
transactionで永続化されます。4 Service consumerは登録直後とcold restart後の
`used=4`をpublic capacity APIで確認します。容量上限に達した後の最初の拒否では
SERVICE capacityの`blocked`もFULL永続化され、内部fault testがPUT/commit failureと
`COMMIT_UNKNOWN`の旧状態／新状態へのrestart収束を検証します。この書込み権限は
SERVICE capacity行だけで、他のcapacity kindには広げません。

POSIX installed consumer gateは次を検証します。

- single-config NOCONFIG producerから、empty / Debug / Release consumer
- NOCONFIGからDebug / Releaseへのstrict identity-map
- Debug producerとRelease producerのmatch / empty / alternate / strict-map
- Ninja Multi-ConfigでDebug / Release
- install metadata・archiveにsource/build絶対pathが残らないこと
- test-only header、symbol、objectがinstall surfaceへ漏れないこと

Host Runtime gateはSQLite OFFでも必ず登録されます。SQLiteの有無をHost Runtime
packageの成立条件にしません。

Fabric installed consumerはpacket-link fixture、storage、clock、execution、TxPermit
gateをconsumer側で実装し、Ninlilのprivate headerや`src/**` include rootを使いません。
controllerからpublic `ninlil_submit()`したApplicationDataがpeer Runtime callbackへ届き、
callbackが作るVERIFIED Receiptがreverse Fabric pathを通って元transactionを
SATISFIEDにします。loss/backpressure、duplicate dedup、restart fenceは既存の
module-owned Fabric/Runtime focused testsをauthorityとし、このexternal happy-path
consumerへ重複実装しません。

Source releaseのclean-roomは、repository内のbuild treeを再利用しません。展開した
archiveからpublic packageをinstallし、`tests/cmake/installed_host_runtime_consumer`
を別build directoryで実行します。同時にarchive内Markdown linkと
`requirements-traceability.yaml`の宣言どおりの状態を検査します。traceabilityの
`partial`は失敗として隠さず、`RELEASE_SUPPORTED`完成証拠へ読み替えません。

## 6. Release evidence and nonclaims

Tag release workflowはSPDX JSON SBOM、checksum、SLSA provenance、
SBOM attestationを生成します。これは次を意味しません。

- maintainer release tagが常に署名済みであること
- production license / legal reviewの完了
- 国内外の無線法規認定
- 物理USB / SX1262 RF / flash / power-cut HILの完了
- Wi-Fi、relay、multi-parent、完全wire fragmentationの完成

機能完成条件は
[Runtime Fabric Completion Contract](34-v2-runtime-fabric-completion.md)、
配布物の正本は
[SDK distribution manifest](sdk-distribution-manifest.md)を参照してください。
