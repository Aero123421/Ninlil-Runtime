# 2026-07-28 OSS compatibility / dependency authority

## 目的

Ninlil Runtimeの対応範囲をREADMEの文章だけで管理せず、release version、公開ABI、
storage schema、platform、feature状態、HIL境界、third-party dependencyを機械的に照合する。
未実施のHILやrelease evidenceをbooleanの書換えだけで完成表示できないことを受入条件とした。

## 追加した正本

- `compatibility-matrix.json`
  - closed completion state
  - version domain
  - Linux / macOS / ESP32-S3 target
  - feature別state、通常evidence、HIL要否、完成依存グラフ
- `tools/compatibility_matrix_gate.py`
  - CMake project version、ESP component version
  - public ABI、Foundation storage schema
  - ESP-IDF exact pin、CI runner、実在evidence path
  - platform / featureごとのimmutable `required_hil`、state ceiling、遷移graph
  - evidence class / path / required contentのclosed authority
  - `HIL_VERIFIED` / `RELEASE_SUPPORTED`のfull commit、test ID、platform、
    PASS、UTC timestamp、artifact SHA-256要件
  - feature omissionと、dependency未完成のままの`RELEASE_SUPPORTED`を拒否
- `tools/third_party_notice_gate.py`
  - OpenSSL / SQLite build authority
  - ESP-IDF、esp_tinyusb、TinyUSBのmanifest / lock / notice一致
  - lock component全集合、direct/transitive、version、component hash、license
  - pinned Syftとdependency inventoryでenrichしたSPDX JSON release経路
- `tools/release_workflow_identity_gate.py`
  - manual refをsingle immutable commitへ解決
  - reusable Host / ESP32-S3 CI、strict Release test、packageの同一commit拘束
  - 全remote Actionのclosed allowlist / full commit SHA
  - source commitとworkflow-definition commitの独立記録
  - checkout/actionlint/ShellCheck pinとShellCheck実行のmutation self-test

## Toolchain pin

- Official Espressif registryの`espressif/idf:v5.5.3` OCI indexを
  `docker manifest inspect`で確認した。
- `linux/amd64` manifest digest:
  `sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb`
- CIはtagではなく上記manifest digestを実行し、runnerを`x86_64`、container内
  `idf.py --version`を`ESP-IDF v5.5.3`として再検査する。
- GitHub公式runner-imagesの
  [support table](https://github.com/actions/runner-images#available-images)
  に基づき、macOS authorityをsupportedな`macos-15` arm64へ移した。

Wi-Fiとpost-attachment radioが未完成のM4/M5を迂回して完成表示されないよう、
`identity-attachment-session-install`をcompatibility matrixの独立featureへ追加した。

## 配布境界

Compatibility matrixは次の両方へ含める。

1. CMake install tree: `${CMAKE_INSTALL_DATADIR}/ninlil/compatibility-matrix.json`
2. tag source release: `tar.gz` / `zip`内のroot直下

Release workflowはpackage前に3 gateとmutation self-testを実行し、archive内にmatrixがexact 1件
あり、dependency inventoryもexact 1件あることを検査する。SPDX SBOM、build identity
metadata、checksum、provenance、SBOM attestationの経路を維持する。
指定branch/tag/refはworkflow冒頭でcommitへ一度だけ解決し、そのcommitを全検証jobへ渡す。
branchが実行中に進んでも、検証対象とpackage対象は変わらない。

## 検証

```text
python3 tools/compatibility_matrix_gate.py check       PASS
python3 tools/compatibility_matrix_gate.py self-test   PASS
python3 tools/third_party_notice_gate.py check         PASS
python3 tools/third_party_notice_gate.py self-test     PASS
python3 tools/release_workflow_identity_gate.py check  PASS
python3 tools/release_workflow_identity_gate.py self-test PASS
python3 tools/spdx_release_sbom.py self-test          PASS
Syft 1.49.0 real output -> enrich -> check            PASS
python3 tools/markdown_link_gate.py check              PASS
temporary CMake configure/install + cmp                PASS
release.yml / ci.yml / esp-idf.yml actionlint+ShellCheck PASS
temporary CMake OSS / link gates                       9/9 PASS
same raw Syft input -> enriched bytes repeatability    PASS
r7 wire/t1b/crypto packaging self-tests                PASS
git diff --check                                       PASS
```

## 非主張

このtrancheはOSS配布の状態表・dependency inventory・release gateを完成候補へ進めるものであり、
Wi-Fi、RF、Relay、Multi-parent、fragmentation、ESP flash durability、法規適合を完成扱いにしない。
各featureは実装・target・HIL・互換性・独立reviewが揃うまでmatrix上の現在stateを維持する。
