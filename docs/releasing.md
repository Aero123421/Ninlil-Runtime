# Release Guide

この文書は、Ninlil Runtimeのsource releaseを再現可能かつ監査可能に作成するための
maintainer向け手順です。特定のapplication、製品、CMake target名には依存しません。

## Releaseの原則

- Releaseは、review済みcommitを不変のGit tagで指します。
- Tagを付けたcommitと、source archive、SBOM、checksum、provenanceのsubjectは
  同一でなければなりません。
- Workflowは任意のbinary targetを推測しません。現在の自動release対象は
  repositoryのsource archiveです。
- CI、host simulation、target compile、HIL、法令適合性を区別し、実施していない
  検証をrelease noteで成功として扱いません。
- 公開済みtagとartifactは置き換えません。修正は新しいversionでreleaseします。

## Versionとtag

### Canonical core version（正本）

配布 identity の **core** は次の4箇所で **完全一致** する
`MAJOR.MINOR.PATCH` です（各成分に leading zero は不可。`0` は可）。

1. `CMakeLists.txt` の `project(ninlil VERSION …)`
2. `compatibility-matrix.json` の `runtime_release`
3. `dependency-inventory.json` の `project.version`
4. `ports/esp-idf/components/ninlil/idf_component.yml` の `version`

Release workflow は `tools/release_version_identity.py` でこれを fail-closed に
照合します。tag の SemVer 形式だけでは不十分です。

### Tag 形式と prerelease / build 方針

- Publish tag: `vCORE[-PRERELEASE][+BUILD]`
  - 例: `v0.1.0`, `v0.1.0-rc.1`, `v0.1.0+build.1`, `v0.1.0-rc.1+exp.sha`
- **CORE は上記 canonical core と完全一致**（`v9.9.9` で `0.1.0` を配ることは不可）
- prerelease / build は **tag と artifact 名**（`ninlil-runtime-<tag>`）にのみ付き、
  CMake package / matrix / inventory / SBOM **project package version** は **core**
  のまま
- SBOM は `--project-version=CORE` と `--source-version=TAG|COMMIT` を保持する
  （Syft `--source-version` を enrich 後も project `sourceInfo` に残す）
- dry-run（`workflow_dispatch`）は tag なし。`source_version` は full commit SHA、
  artifact base は `ninlil-runtime-dry-run-<12hex>`
- 過去の legacy tag は履歴として保持しますが、新しい release で再利用しません

Release tagはannotated tagとし、署名可能なmaintainerは署名付きtagを使用します。

```sh
# core が 0.1.0 のときのみ有効
git tag -s v0.1.0 -m "Ninlil Runtime v0.1.0"
git push origin v0.1.0
```

署名環境を利用できない場合は `git tag -a` を使用し、その理由をrelease tracking
Issueへ記録します。

## Release前checklist

Release stewardは次を確認します。

1. Release scope、version、steward、対象commitをtracking Issueに記録した。
2. `CHANGELOG.md` の `Unreleased` を整理し、利用者影響と既知の制限を記載した。
3. Public API / ABI、wire、storage format、support範囲の互換性を評価した。
4. Release scopeに必要な通常CI、sanitizer、target build、HILが完了した。
5. HIL未実施、LAB_ONLY、experimental、unsupportedをrelease noteに明示した。
6. `LICENSE`（full Apache-2.0 bytes / pinned SHA-256）、`NOTICE`（exact
   obligations）、`THIRD-PARTY-NOTICES.md`、security/support文書を確認した。
7. Security Advisoryに公開を妨げる未解決事項がないことを確認した。
8. Release commitからdry run artifactを作り、内容をreviewした。
9. `python3 tools/compatibility_matrix_gate.py check`と`self-test`が成功し、
   `compatibility-matrix.json`のfeature状態・platform・HIL evidenceがrelease noteと一致した。
   SDK distribution manifestの live ```json``` authority
   (`ninlil-sdk-distribution-manifest-v1`) も確認した（HTML commentのみは不可）。
10. `python3 tools/third_party_notice_gate.py check`と`self-test`が成功し、
    direct/transitive lock、third-party notice、executed pinned Syft identity
    （`syft-version: v1.49.0` + download-syft full SHA）が一致した。
11. `python3 tools/release_workflow_identity_gate.py check`と`self-test`が成功し、
    Host / ESP32-S3 / strict Release / packageがsingle immutable commitを共有し、
    executed `uses`/`ref` allowlist以外の Action/ref を拒否した。
    あわせて `python3 tools/release_version_identity.py self-test` で tag core と
    CMake/matrix/inventory/ESP の一致を確認した。
12. `python3 tools/spdx_release_sbom.py self-test`が成功し、実際に生成したSBOMを
    `check`して既知package/version/license/hashの欠落と`NOASSERTION`を拒否した。
    同一sourceは timestamp/namespace 非決定性を除いた後 byte-identical である。
    publish 時は `--project-version` / `--source-version` が core と tag/commit に
    一致する。
13. `python3 tools/release_distribution_authority_gate.py check`と`self-test`が
    成功し、禁止語彙、archive payload、tests-OFF surface、Markdown local link、
    compatibility、NOTICE、workflow identity、SBOM、public SDK boundaryを
    fail-closed順序で全件実行した。
14. source `tar.gz` / `zip`の全member path/bytesが一致し、uid/gid/mtime、
    通常file `0644` / shebang付きscript `0755`、member順、gzip/zip metadataが
    canonicalである。必須のpublic install/release/traceability文書が欠けていない。
15. shipped archiveのclean-roomでtests-OFF packageをinstallし、別build directoryの
    public-API-only consumerが`create → step → destroy`を完了した。
    `traceability_check`の`partial`は宣言どおり保持され、完成へ読み替えていない。

## Dry run

GitHub Actionsの **Release** workflowを `workflow_dispatch` で実行します。任意の
branch、tag、または完全なcommit SHAを `ref` に指定できます。空欄なら選択した
branchのcommitを使用します。

Workflowは指定refを最初にexact source commitへ1回だけ解決し、workflow definitionの
commitも別のfull SHAとして固定・記録します。その同じsource commitを通常PRと同じ
full Linux/macOS CI reusable workflow、pinned ESP-IDF ESP32-S3 target reusable workflow、
GCC 13のstrict Release buildとconfigureされた全CTestへ渡します。branchがworkflow実行中に
進んでも、検証対象とpackage対象は変わりません。いずれかのcalled workflow失敗、Testが
0件、build失敗、または1件でもtest失敗ならpackageを作りません。成功後、dry runは次を
生成し、workflow artifactとして14日間保存します。

- deterministic source `tar.gz`
- source `zip`
- SPDX JSON SBOM
- source commitとworkflow-definition commitを記録したbuild metadata JSON
- `SHA256SUMS`

Dry runはGitHub Releaseを作成せず、tagを変更せず、OIDC provenance attestationを
発行しません。Attestationを含む完全なpublish経路はtag pushでのみ実行されます。

Dry run artifactを展開し、秘密情報、build tree、不要なgenerated fileがないこと、
SBOMのproject名・version・license情報、dependency inventoryとの一致、build metadataの
2つのcommit、checksum検証を確認します。Archiveはcommit treeだけを入力にし、
SBOM/build metadataはclean-tree検査が終わるまでrepository外へstageします。

```sh
sha256sum -c ninlil-runtime-*.SHA256SUMS
```

macOSでは `shasum -a 256 -c ninlil-runtime-*.SHA256SUMS` を使用できます。

## Publish

`v*` tagのpushで `.github/workflows/release.yml` が起動します。Workflowはtag名を
SemVerとして再検査し、checkout commitがtag targetと一致しない場合はfail closedに
します。

Release workflowはtag commit上でfull Linux/macOS CIとpinned ESP32-S3 target CIを
再利用し、通常branch CIが以前成功したという外部状態だけに依存しません。
Verify / Package jobはread-only権限でstrict Release test、source archive、
dependency inventoryでenrichしたSPDX SBOM、source/workflow identity metadata、
checksumを作ります。ESP-IDF target CIはofficial imageのlinux/amd64 OCI manifest
digestを固定し、container内のESP-IDF versionも検査します。後続の権限は責務ごとに
分離します。

- Attest job: `contents: read`、Sigstore署名用 `id-token: write`、
  GitHub artifact用 `attestations: write`
- Publish job: draft GitHub Releaseとassetに必要な `contents: write` のみ

Attest jobはchecksumを再検証し、次の2種類を独立して発行します。

1. Source archive、SBOM、checksumをsubjectとするSLSA build provenance
2. `tar.gz`と`zip`をsubjectとし、SPDX JSONをpredicateとするSBOM attestation

それぞれのSigstore bundleを `.provenance.sigstore.json` と
`.sbom-attestation.sigstore.json` という区別可能なrelease assetへ含めます。
Publish jobは完成した7 filesを再検証し、draft Releaseへ全assetを追加してから
最後に公開します。Pre-release suffixを持つtagはGitHub上でもpre-releaseに設定します。

## 公開後の検証

1. Release tagとtarget commitがtracking Issueの記録と一致する。
2. 全assetがあり、`SHA256SUMS`が成功する。
3. GitHub CLIでattestationを検証できる。
4. Source archive内のversion、license、notice、release文書が正しい。
5. Release noteのsupport範囲と既知の制限が実際の検証証跡と一致する。

```sh
RELEASE_TAG=v0.1.0

gh attestation verify \
  "ninlil-runtime-${RELEASE_TAG}.tar.gz" \
  --repo Aero123421/Ninlil-Runtime

gh attestation verify \
  "ninlil-runtime-${RELEASE_TAG}.tar.gz" \
  --repo Aero123421/Ninlil-Runtime \
  --predicate-type https://spdx.dev/Document/v2.3
```

## 失敗時の扱い

- Packageまたはattestation失敗時はtagを移動せず、原因を修正して新しいversionを
  作ります。
- Asset upload後に失敗した場合、workflowは公開前のdraftで停止します。内容を確認し、
  不完全なdraftを削除してから同じ不変tagでworkflowを再実行できます。
- 一度公開したReleaseやtagに異なるbytesを上書きしません。
- Credential漏えいまたはsecurity事故は、通常Issueではなく
  [SECURITY.md](../SECURITY.md)の非公開手順で扱います。

## Action pinの更新

Workflow内のthird-party Actionはすべて完全なcommit SHAへpinします。更新Pull Request
では、upstream release note、Action sourceの差分、必要権限、Node runtime、取得する
外部binaryのversionをreviewし、dry runを成功させます。Major tagやmutable tagだけを
`uses:`へ指定してはいけません。
