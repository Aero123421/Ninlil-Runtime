# Ninlil Host Runtime SDK

状態: 現行 `main` の installable Host SDK 利用ガイド

この文書は、履歴リリース `v1.0-lab-rc2` ではなく、現行source treeから
installする Host Runtime SDK を説明します。CMake packageとしての生成・利用は
検証済みですが、物理USB/RF、Wi-Fi、relay、multi-parent、完全fragmentation、
production法規適合まで完成したという主張ではありません。

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

## 4. Exported targets and dependencies

| Target | 条件 | 内容 |
| --- | --- | --- |
| `Ninlil::ninlil` | 常時 | Public header用INTERFACE target |
| `Ninlil::runtime` | Host Runtime有効時 | Public Host Runtime static archive |
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
| `host_runtime_tests_off_installed_consumer` | SQLite OFF、tests OFF install、public APIだけのmemory storageで`create → step → destroy` |
| `host_runtime_tests_off_installed_consumer_sqlite` | SQLite ON時、上記に加えてinstalled SQLite provider |
| `posix_sqlite_storage_installed_consumer` | POSIX providerのinstall surface、path hygiene、external consumer matrix |
| `runtime_private_subproject_smoke` | `add_subdirectory`時のpublic/private target境界 |

POSIX installed consumer gateは次を検証します。

- single-config NOCONFIG producerから、empty / Debug / Release consumer
- NOCONFIGからDebug / Releaseへのstrict identity-map
- Debug producerとRelease producerのmatch / empty / alternate / strict-map
- Ninja Multi-ConfigでDebug / Release
- install metadata・archiveにsource/build絶対pathが残らないこと
- test-only header、symbol、objectがinstall surfaceへ漏れないこと

Host Runtime gateはSQLite OFFでも必ず登録されます。SQLiteの有無をHost Runtime
packageの成立条件にしません。

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
