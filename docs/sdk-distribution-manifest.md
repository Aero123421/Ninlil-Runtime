# Ninlil SDK distribution manifest

状態: 現行 `main` の installable Host SDK 配布manifest

このmanifestは、現行source treeの `cmake --install` とtag release workflowを
対象にします。履歴release `v1.0-lab-rc2` の配布物は
[V1 LAB distribution manifest](v1-lab-distribution-manifest.md)を参照してください。

## 1. CMake compatibility

Repository build / CTestとinstalled package consumerの正式下限は、どちらも
CMake 3.20です。Host support対象はLinux / macOSです。

## 2. Install tree

`GNUInstallDirs`の変数で配置を決定します。

| 成果物 | 配置 | 条件 |
| --- | --- | --- |
| CMake package metadata | `${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil/` | 常時 |
| Core public headers | `${CMAKE_INSTALL_INCLUDEDIR}/ninlil/` | 常時 |
| Host Runtime archive | `${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}ninlil_runtime${CMAKE_STATIC_LIBRARY_SUFFIX}` | `NINLIL_BUILD_HOST_RUNTIME=ON` |
| POSIX SQLite archive | `${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}ninlil_posix_sqlite_storage${CMAKE_STATIC_LIBRARY_SUFFIX}` | SQLite provider生成時 |
| POSIX SQLite factory header | `${CMAKE_INSTALL_INCLUDEDIR}/ninlil_posix_sqlite_storage.h` | SQLite provider生成時 |
| Apache-2.0 license | `${CMAKE_INSTALL_DATADIR}/licenses/ninlil/LICENSE` | 常時 |
| Project notice | `${CMAKE_INSTALL_DATADIR}/licenses/ninlil/NOTICE` | 常時 |
| Third-party notices | `${CMAKE_INSTALL_DATADIR}/licenses/ninlil/THIRD-PARTY-NOTICES.md` | 常時 |
| Compatibility matrix | `${CMAKE_INSTALL_DATADIR}/ninlil/compatibility-matrix.json` | 常時 |
| Dependency inventory | `${CMAKE_INSTALL_DATADIR}/ninlil/dependency-inventory.json` | 常時 |

実際のstatic archive prefix / suffixはtarget platformが決定します。上表の変数を
`lib/*.a`へ固定して解釈しません。

## 3. Exported CMake targets

| Target | Export |
| --- | --- |
| `Ninlil::ninlil` | 常時 |
| `Ninlil::runtime` | Host Runtime有効時 |
| `Ninlil::ninlil_posix_sqlite_storage` | SQLite provider生成時 |

`Ninlil::runtime` はOpenSSL major version 3の `OpenSSL::Crypto` を推移依存として
解決します。現行は単一archive granularityです。SQLite targetはSQLite3を
推移依存として解決します。OpenSSL / SQLiteのlibrary本体は配布物に同梱しません。

## 4. Not exported

次はinstallable public SDK surfaceではありません。

- `ninlil_runtime_private`
- private Runtime / model / transport / radio headers
- C4/C5/C6の個別private target / header
- test fixtures、fault injection seams、oracles、generated test artifacts
- LAB platform、loopback bearer、examples executable
- ESP-IDF componentと実機firmware image

Host Runtime archiveにhost simulation用の一部内部software-path implementation
unitが含まれることは、それらを独立したpublic C4/C5/C6 moduleとしてexportする
こと、または物理USB/RFの完成を意味しません。

## 5. Source repository

| 区分 | パス |
| --- | --- |
| Public ABI | `include/ninlil/` |
| Runtime implementation | `src/runtime/`, `src/model/` |
| Internal transport / radio | `src/transport/`, `src/radio/`, `drivers/` |
| POSIX ports | `ports/posix/` |
| ESP-IDF port | `ports/esp-idf/` |
| Package consumers | `tests/cmake/` |
| Package gates | `cmake/installed_*_smoke.cmake` |
| License documents | `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md` |
| Compatibility authority | `compatibility-matrix.json`, `tools/compatibility_matrix_gate.py` |
| Dependency authority | `dependency-inventory.json`, `tools/third_party_notice_gate.py`, `tools/spdx_release_sbom.py` |

## 6. Release artifacts

Tag release workflowは次を生成・検証します。

- source `tar.gz` / `zip`
- source archive内のmachine-readable compatibility matrix
- SPDX JSON SBOM
- source / workflow-definition commit build metadata
- checksum
- source archive / SBOMをsubjectとするSLSA provenance
- archiveをsubjectとするSBOM attestation

詳細は [Release Guide](releasing.md) を参照してください。SBOM / attestationの
生成と、maintainer tagの必須署名方針、production license / legal reviewは
別の保証です。

## 7. Required package gates

| Gate | 必須証拠 |
| --- | --- |
| Host Runtime SQLite OFF | tests-OFF install、SQLite target/header/archive非依存、external memory consumer lifecycle |
| Host Runtime SQLite ON | tests-OFF install、optional SQLite target、external memory/SQLite consumer lifecycle |
| POSIX installed consumer | NOCONFIG / Debug / Release / strict-map / Multi-Config、surface・symbol・path hygiene |
| Private subproject | public/private target、include、flags、source authority境界 |
| OSS authority | compatibility matrix、direct/transitive dependency notice、pinned SPDX SBOM経路 |
| Workflow / release identity | actionlint + ShellCheck、入力refのsingle immutable commit解決、Host / ESP32-S3 / packageの同一commit再検証 |

Package gateがgreenでも、物理HIL、field SLO、無線法規、Wi-Fi、relay、
multi-parent、完全fragmentationの完成は主張しません。

## 8. Source identity record

配布と検証の前に、対象commitをfull SHAで記録します。

```bash
git status --short
git rev-parse HEAD
git show -s --format='%H %cI %s' HEAD
```

Tag releaseでは、tagが同じcommitを指すことも記録します。

```bash
tag=vX.Y.Z
commit="$(git rev-parse HEAD)"
test "$(git rev-list -n 1 "$tag")" = "$commit"
git show -s --format='%H %cI %s' "$tag"
```

未tagのcandidate検証は `tag=none` と明記します。dirty treeからrelease artifactを
作らず、必要な検証差分がある場合はdiffと基準commitを別々に保存します。

## 9. Reproducible package gate commands

以下はshared source tree外のbuild directoryを使います。NOCONFIGは
`CMAKE_BUILD_TYPE`を指定しません。

```bash
# Ninja NOCONFIG: POSIX consumerがempty / Debug / Release / strict-mapを実行
cmake -S . -B ../ninlil-package-noconfig -G Ninja \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
cmake --build ../ninlil-package-noconfig --parallel
ctest --test-dir ../ninlil-package-noconfig --output-on-failure \
  -R '^(host_runtime_tests_off_installed_consumer(_sqlite)?|posix_sqlite_storage_installed_consumer|runtime_private_subproject_smoke)$'

# Ninja Debug / Release
for config in Debug Release; do
  build="../ninlil-package-${config}"
  cmake -S . -B "$build" -G Ninja \
    -DCMAKE_BUILD_TYPE="$config" \
    -DNINLIL_BUILD_TESTS=ON \
    -DNINLIL_BUILD_HOST_RUNTIME=ON \
    -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
  cmake --build "$build" --parallel
  ctest --test-dir "$build" --output-on-failure \
    -R '^(host_runtime_tests_off_installed_consumer(_sqlite)?|posix_sqlite_storage_installed_consumer|runtime_private_subproject_smoke)$'
done

# Ninja Multi-Config: producer / consumerをDebugとReleaseの両方で実行
cmake -S . -B ../ninlil-package-multi -G 'Ninja Multi-Config' \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
cmake --build ../ninlil-package-multi --config Debug --parallel
ctest --test-dir ../ninlil-package-multi -C Debug --output-on-failure \
  -R '^(host_runtime_tests_off_installed_consumer(_sqlite)?|posix_sqlite_storage_installed_consumer|runtime_private_subproject_smoke)$'
cmake --build ../ninlil-package-multi --config Release --parallel
ctest --test-dir ../ninlil-package-multi -C Release --output-on-failure \
  -R '^(host_runtime_tests_off_installed_consumer(_sqlite)?|posix_sqlite_storage_installed_consumer|runtime_private_subproject_smoke)$'

# SQLite OFFでもHost Runtime install consumerは必須
cmake -S . -B ../ninlil-package-sqlite-off -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DNINLIL_BUILD_TESTS=ON \
  -DNINLIL_BUILD_HOST_RUNTIME=ON \
  -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=OFF
cmake --build ../ninlil-package-sqlite-off --parallel
ctest --test-dir ../ninlil-package-sqlite-off --output-on-failure \
  -R '^(host_runtime_tests_off_installed_consumer|runtime_private_subproject_smoke)$'
```
