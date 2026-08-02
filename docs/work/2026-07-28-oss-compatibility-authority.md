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
  - feature status / ADR 状態行 / README 台帳セルへの **exact anchored** 照合
    （任意substringではなく、status-onlyのoverclaim/underclaimを拒否）
  - README / ADR status: **canonical leading state** with qualifiers structurally
    outside the state; peer mixed-token forms such as
    `HOST_CANDIDATE / RELEASE_SUPPORTED` are rejected
  - independent-review: **structured** `label + GO|NO-GO + P0/P1/P2` authority
    (stale whole-file / second-line / comment P0=0 text does not satisfy)
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
- `tools/esp_idf_component_packaging_gate.py`
  - official ESP-IDF containerを **immutable digest** + **linux/amd64** で拘束
  - authority is the **executable** `docker run` command after comment-strip /
    line-continuation join / tokenization (comments do not count)
  - 現行参照:
    `docker.io/espressif/idf@sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb`
  - exact `--platform linux/amd64` on that same executed command
  - tag-only / floating / wrong digest / wrong repo / arm64 / missing platform /
    values moved to comments / extra alternate `docker run` の mutation を拒否

## Toolchain pin

- Official Espressif registryの`espressif/idf:v5.5.3` OCI indexを
  `docker manifest inspect`で確認した。
- `linux/amd64` manifest digest:
  `sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb`
- CIとactive docsはtagではなく上記manifest digestを実行し、runnerを`x86_64`、
  platform authorityを`linux/amd64`、container内`idf.py --version`を
  `ESP-IDF v5.5.3`として再検査する。
- GitHub公式runner-imagesの
  [support table](https://github.com/actions/runner-images#available-images)
  に基づき、macOS authorityをsupportedな`macos-15` arm64へ移した。

Wi-Fiとpost-attachment radioが未完成のM4/M5を迂回して完成表示されないよう、
`identity-attachment-session-install`をcompatibility matrixの独立featureへ追加した。

## 2026-07-29 authority fix scope（independent audit follow-up）

Reason: independent audit remained NO-GO after baseline gates: status parsers
accepted visible STATE+RELEASE_SUPPORTED, live NO-GO with GO hidden in HTML
comments / same-line trailing stale GO; ESP parser accepted dual
`--platform`/`--platform=`, digest-as-argv, list-item/inline/folded YAML decoys,
and wrapper/separator extra docker invocations.

### Parser contract (this repair)

**Compatibility / live markdown status**
- Strip HTML comments; scan **all** live `状態:` lines including indented.
- Exactly one live `状態: **body**` line; text after closing `**` must not carry
  completion states, GO/NO-GO, or structured `P0/P1/P2` counts.
- Rejects: bold SPEC_ACCEPTED + live `— RELEASE_SUPPORTED`; bold Proposed + live
  RELEASE_SUPPORTED; review GO bold + trailing NO-GO; second indented
  ` 状態: **…**` lines.
- Blockquote `> 状態:` is **not** an authoritative status location; claim-like
  smuggling (`> 状態: **RELEASE_SUPPORTED**`) is rejected.
- Independent-review: exactly one live GO|NO-GO + exact counts in the bold body.
- Domain review four-file manifest: `ninlil-domain-review-manifest-v1` via
  `tools/domain_store_schema1_review_manifest_gate.py` (path+length+sha256 frames).
- LICENSE: full Apache-2.0 bytes with pinned SHA-256
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`
  (one-line "Apache License" stubs reject).
- NOTICE: exact obligations (Ninlil, Apache License Version 2.0, LICENSE,
  THIRD-PARTY-NOTICES.md).
- SDK distribution manifest: live ```json``` block
  `ninlil-sdk-distribution-manifest-v1` (HTML-comment-only authority rejects).

**ESP docker / workflow**
- Sole launcher: `tools/esp_idf_ci_docker_run.sh` (workflow run must be exact
  `bash tools/esp_idf_ci_docker_run.sh` once).
- Script holds the only docker run: immutable IMAGE digest + `--platform linux/amd64`.
- Semantic YAML `run` (incl. Unicode `\u0072un`); alias / expand_aliases /
  `do''cker` / eval / bash -c / env-borne docker fail closed.

**Release workflow identity**
- Vendored PyYAML semantic tree (Unicode escapes, anchors, aliases, merge,
  duplicate-key reject). Hand-rolled uses/ref regex is not authority.
- Exact step context: `uses`, `with.ref`, `with.persist-credentials` only —
  `env.ref` / `env.persist-credentials` decoys never satisfy.
- Closed allowlist + full commit SHA; extra action count 0
  (incl. `"\u0075ses": attacker/...`).

**Third-party / Syft**
- Only the download-syft step's `with.syft-version` (Unicode key resolve).
- Checkout / other-step `syft-version` decoys reject.

**SPDX / SBOM determinism**
- Closed inventory packages + canonical relationships only (includes vendored
  `tools/_vendor` PyYAML 6.0.2 MIT with tree SHA-256).
- Syft packages are reconciled: in-scope discoveries (inventory names / vendored
  paths) cannot be dropped without inventory entry or machine-readable
  `syft_reconciliation.justified_exclusions`.
- Global SPDXID uniqueness; all relationship endpoints resolve; no dangling
  refs; no extra random packages; no `builtDate` / volatile fields.
- Two-run self-test with mutated timestamp/namespace is byte-identical.
- Independent re-audit / `HOST_CANDIDATE` promotion is **not** claimed.

**Status / NOTICE**
- `状態:` authority is outside HTML comments, blockquotes, and fenced code.
- NOTICE: exact bytes/hash + affirmative clauses (negation smuggling rejects).

**Self-tests (P1-3)**
- In-memory overlays / pure string mutations only — **never** write ROOT
  README/ADR/review/workflow even transiently.
- Assert inode/size/mode/mtime_ns/ctime_ns/sha256 unchanged before/after.

**Independent-audit closure: pending** (local gates green are not remote audit
re-GO or release-support approval).
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
python3 tools/compatibility_matrix_gate.py check/self-test     PASS (local)
python3 tools/esp_idf_component_packaging_gate.py check/self-test PASS (local)
  (in-memory mutations only; source metadata invariant)
python3 tools/third_party_notice_gate.py check/self-test       PASS (local)
python3 tools/release_workflow_identity_gate.py check/self-test PASS (local)
python3 tools/spdx_release_sbom.py self-test                   PASS (local; two-run)
git diff --check                                               PASS (local)
```

This section is a local ledger only, not remote release or independent-audit evidence.

## 非主張

このtrancheはOSS配布の状態表・dependency inventory・release gate・authority
照合の厳密化であり、Wi-Fi、RF、Relay、Multi-parent、fragmentation、ESP flash
durability、法規適合、HIL PASS、release supportを完成扱いにしない。
各featureは実装・target・HIL・互換性・独立reviewが揃うまでmatrix上の現在stateを維持する。
GitHub Actionsの`workflow_dispatch` dry runは、review済みcommitへ統合・pushされるまで
実行していない。上記local verificationはremote release実行またはpublish evidenceの
代わりではない。Independent audit re-GO / release-support approvalは行わない。
`RELEASE_SUPPORTED` および HIL 完成は claim しない。

## 2026-07-29 OSS software-ready completion audit

公開面の追加監査で、既存gateがgreenでも残る次の穴を修正した。

- Release package jobがrepository内`dist/`を作成した後に
  `--require-clean-worktree`を実行していた。SBOM/build metadataを
  `${RUNNER_TEMP}`へstageし、immutable git-tree archive成功後だけ`dist/`を作る。
- ordered distribution authorityへ`markdown_link_gate`のcheck/self-testを追加した。
- tar/zipの必須4file以外も含む全path/bytes一致と、canonical
  uid/gid/mtime/mode/order/gzip/zip metadataを検査する。
- source archive必須inventoryへpublic install consumer、release/install docs、
  `CHANGELOG.md`、`CONTRIBUTING.md`、`requirements-traceability.yaml`を追加した。
- clean-roomはarchive内の全Markdown local link、`traceability_check`、
  tests-OFF installに対する独立public consumerの`create → step → destroy`を実行する。
- NOTICEの対象を、linked library、committed manifestで解決するtarget component、
  source treeへ同梱するvendored toolingへ限定し、一般的なbuild toolまで
  inventory済みと読める過剰表現を除いた。
- SPDXは既知のvendored PyYAML download locationをinventoryから保持し、改変を拒否する。
- source archiveのmodeは内容決定的に通常file `0644`、shebang付きscript `0755`
  とし、展開後にdirect CTest scriptを実行不能にしない。非canonical modeを拒否する。
- gzip XFL / OS、portable prefix、`./`・backslash等の非canonical member spellingも
  mutation self-testで拒否する。vendor upstreamのCRLF/空白は`.gitattributes`で
  whitespace検査だけ除外し、通常diffのreview可視性と原文hashを維持する。

この監査はlocal software/package候補の完成であり、remote GitHub Actionsの成功、
tag publish、独立review、物理HIL、法規適合、各private featureの
`RELEASE_SUPPORTED`昇格を主張しない。`requirements-traceability.yaml`は
Foundation PR1 scopeのままで、宣言済み`partial` 1件を隠さない。
