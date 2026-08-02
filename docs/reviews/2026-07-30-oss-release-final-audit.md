# OSS package / documentation / release final independent audit

監査日: 2026-07-30  
対象repository: `Aero123421/Ninlil-Runtime`  
対象branch: `codex/runtime-completion`  
監査開始時local HEAD: `e756aa06d38fdf1b6b3f1722aa8daf5af032bd38`  
監査開始時remote branch: `b04e6da881c9a7bc4515172bc0d5965576ea2a2b`

## 結論

**現時点のrelease判定は NO-GO** とする。

- P0: 0件
- P1: 4件
- P2: 3件

Apache-2.0、NOTICE、third-party inventory、SPDX生成gate、CMake install
surface、public C ABI gate、worktree archiveの決定性とclean-room package testには、
今回確認した範囲でreleaseを直ちに止める欠陥は見つからなかった。

NO-GOの主因は、現在の候補が369 status entriesを持つ変更途中のworktreeであり、
immutable commit treeの配布authority gateが実際に失敗すること、同じ候補commitに
対するremote Linux/macOS/ESP32-S3/release dry run証拠がないこと、および巨大な
D3-S4 oracleの標準testがsource treeを書き換え、remote CIの時間・資源余裕も未確認な
ことである。

`compatibility-matrix.json:229-240`の
`oss-package-docs-release-ci = HOST_CANDIDATE`は現状と整合しており、
`RELEASE_SUPPORTED`へは昇格させてはならない。

### Severity

- **P0**: 法的配布不能、公開asset改ざん、秘密情報混入など、直ちに公開を禁止する問題
- **P1**: release候補の再現性、CI、配布物、公開文書の整合性を満たさず、公開前に必須修正
- **P2**: 現releaseを単独では止めないが、次の互換性・保守性事故を防ぐために修正すべき問題

## P1 findings

### P1-1: immutable release candidateが存在せず、commit-tree authorityが失敗する

#### Evidence

- 監査開始時の`git status --short`は369 entries。tracked、staged、untrackedが
  混在し、release候補の正確なbyte集合がcommitとして固定されていない。
- local HEADは`e756aa06...`、remote branchは`b04e6da...`で一致しない。
- current worktreeからのarchive two-runとclean-roomは成功したが、配布workflowが
  入力にするpure Git treeではない。
- 次のauthority commandは、HEADの`NOTICE` SHA-256がcurrent pinned authorityと
  一致せず失敗した。

```text
archive NOTICE: sha256 mismatch
got=48f0e0afc687fde4a9eaefdb094793270b0c20de5d2622a336a4031018efed2a
expected=7fe5c13ffc658808747eb361dd14ed17ea912a5e5fe4d8f7a5405bfbb6185319
source=git:HEAD files=755
```

`.github/workflows/release.yml:22-75`はsource commitとworkflow commitを固定し、
同一sourceをLinux/macOSとESP32-S3へ渡す正しい構造である。しかし、現在の変更は
そのimmutable boundaryへ到達していない。

#### Reproduction

```sh
git rev-parse HEAD
git rev-parse origin/codex/runtime-completion
git status --short
python3 tools/release_distribution_authority_gate.py check
python3 tools/release_archive_payload_gate.py \
  build-from-git --two-run --source git --treeish HEAD \
  --prefix ninlil-runtime-authority
```

#### Minimal acceptance

1. intended changeをreview可能なcommitへ固定し、`git status --short`を空にする。
2. remoteへpushし、local/remote/candidate SHAを完全一致させる。
3. そのcommitで上記2 command、`git diff --check`、archive clean-roomを成功させる。
4. 成功logにfull commit SHA、archive SHA-256、test countを記録する。
5. worktree overlayの成功をcommit-tree成功の代用にしない。

### P1-2: 現候補commitのremote CI / release dry run / public asset evidenceがない

#### Evidence

- PR #114で確認できたLinux/macOS CIとESP-IDF成功はremote
  `b04e6da881c9a7bc4515172bc0d5965576ea2a2b`に対するもので、current local
  candidateではない。
- `gh run list --workflow release.yml`はdefault branchにworkflowがまだ存在しないため
  HTTP 404となり、current release workflowの`workflow_dispatch`実績を確認できなかった。
- 公開済みの`v1.0-lab-rc2`はhistorical prereleaseで、current packageのcustom
  release assetsを持たない。GitHubが自動生成するsource archiveはcurrent
  `tar.gz` / `zip` / SPDX / metadata / checksums / attestationsの証拠ではない。
- `docs/work/2026-07-28-oss-compatibility-authority.md:138-139`,
  `:173-175`, `:202-205`もremote dry run、independent re-GO、publish evidenceが
  pendingであることを正しく明記している。
- workflow自体はstrict test、SBOM、決定的archive、attestation、publishを分離している
  （`.github/workflows/release.yml:76-147`, `:149-275`, `:276-405`,
  `:405-495`, `:496-530`）。不足は設計ではなく、同一immutable SHAでの実行証拠である。

#### Reproduction

```sh
gh pr view 114 --json headRefOid,statusCheckRollup
gh run list --workflow release.yml --limit 20
gh release view v1.0-lab-rc2 --json isPrerelease,assets,targetCommitish
```

#### Minimal acceptance

1. P1-1で固定したcommitをpushし、同じfull SHAでLinux、macOS、ESP32-S3のrequired
   checksをすべて成功させる。
2. release workflowをdefault branchから`workflow_dispatch`し、`ref`には候補のfull
   SHAを指定する。
3. dry-runから`tar.gz`、`zip`、SPDX JSON、build metadata、`SHA256SUMS`をdownloadし、
   `docs/releasing.md:98-130`どおりにchecksum、source/workflow SHA、license、
   dependency inventory、archive member equivalenceを独立確認する。
4. publish前にtag pathを実行し、provenanceとSBOM attestationを含む7 filesを検証する
   （`docs/releasing.md:132-177`）。draft releaseで確認後にだけ公開する。

### P1-3: 51.48 MiBの単一generated oracleと標準self-testがrelease CI境界を超えている

#### Evidence

`spec/vectors/domain-scan-crossrow-v1.json`のcurrent worktree:

- 53,984,354 bytes（51.48 MiB）
- 1,179,907 lines
- SHA-256:
  `f0655bfa8fd61f7a09a82401effad78a44ed8edaf807b02047515c045245a7a0`
- HEAD版は15,876,588 bytes、436,921 linesで、current diffは
  742,990 insertions / 4 deletions
- gzip `-9`では約1.99 MiBであり、worktree source archive全体も
  `tar.gz`約8.47 MiB、`zip`約9.49 MiB。したがってrelease download容量自体が主問題ではない。

GitHubは50 MiB超のfileをpush warning対象、100 MiB超を通常Gitのhard blockとしている。
current fileはhard block未満だがwarning thresholdを超え、1回の再生成で巨大blobを履歴へ
追加し続ける。

- [About large files on GitHub](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
- [Repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits)

local Apple Siliconでの実測:

- `emit-c-fixture`: 約6.37秒、max RSS約615 MiB
- `check`: 約4.47秒、max RSS約615 MiB
- `self-test`: 約121.62秒、max RSS約1.64 GiB
- generated C header: 39,460,472 bytes（37.63 MiB）

標準CTestのtimeoutは180秒しかなく
（`CMakeLists.txt:4042-4060`）、local実測に対する余裕は約58秒である。
fixtureもconfigure/build graphで再生成される
（`CMakeLists.txt:4269-4323`）。current remote Linux/macOS candidateでは
このサイズの実測がない。

さらにself-testは`tools/domain_scan_crossrow_d3s4_vector_gen.py:39-43`で
source root配下の`tmp-a2/qa-regression-log-a2a2.txt`を固定出力先にし、
`:10810-10833`でdirectory/fileを作成する。標準CTestを実行するとclean source treeに
untracked fileが残り、test hermeticityを満たさない。

#### Reproduction

```sh
wc -l -c spec/vectors/domain-scan-crossrow-v1.json
shasum -a 256 spec/vectors/domain-scan-crossrow-v1.json
git diff --numstat -- spec/vectors/domain-scan-crossrow-v1.json
/usr/bin/time -l python3 tools/domain_scan_crossrow_d3s4_vector_gen.py self-test
git status --short -- tmp-a2 spec/vectors/domain-scan-crossrow-v1.json
```

#### Minimal acceptance

1. canonical oracleのcount、order、hash、negative casesを失わず、domain/slice単位の
   決定的な複数artifactへ分割し、1 Git blobを50 MiB未満にすることを推奨する。
   単一fileを維持するなら、理由、上限、更新頻度、review方法をAccepted decisionとして
   明記し、100 MiBへ近づく前にfailするsize gateを追加する。
2. Git LFS pointerだけをsource archiveへ入れる設計にはしない。offline clean-roomで
   exact oracle bytesが得られることを維持する。
3. self-test logはCTest binary directoryまたはOS temporary directoryへ出し、
   test前後の`git status --short`が同一であることを自動testにする。
4. 同一immutable commitのLinux/macOS runnerでwall timeとpeak RSSを採取し、
   slowest runnerのP95がtest timeoutの50%以下、peak RSSがjob memoryの50%以下となる
   明示budgetを設定する。満たさない場合はgeneratorのstreaming化、fixtureの再生成回数削減、
   test shard化を行う。
5. 分割後のfull 468-vector semantic bridge、two-run byte determinism、negative mutation、
   archive clean-roomを再実行する。

### P1-4: READMEの「次の必須gate」が既存実装・test evidenceと矛盾する

#### Evidence

`README.md:31`はPortable Core / Host Runtimeについて、tests-OFF installed consumerを
「4 Service登録、submit、dedupe、query/list、memory/SQLite cold restartまで拡張」する
ことが今後必要だと記載する。

一方、`docs/host-runtime-sdk.md:133-170`は、そのexact scopeを次の既存testが検証すると
記載している。

- `host_runtime_tests_off_installed_consumer`
- `host_runtime_tests_off_installed_consumer_sqlite`
- `host_runtime_tests_off_installed_consumer_domain_on`
- release archive clean-room consumer

今回のfresh macOS Release buildでも上記installed consumer、private subproject、
POSIX SQLite installed consumerは成功し、worktree archive clean-roomも成功した。
remote/independent evidenceがpendingであることは正しいが、「実装拡張が未実施」と
「実装済みで再確認待ち」を混同すると、公開completion ledgerが事実を表さない。

#### Reproduction

```sh
rg -n "tests-OFF installed consumer|4 Service|cold restart" \
  README.md docs/host-runtime-sdk.md
ctest --test-dir <fresh-build> --output-on-failure -R \
  'host_runtime_tests_off_installed_consumer|runtime_private_subproject_smoke|posix_sqlite_storage_installed_consumer'
```

#### Minimal acceptance

`README.md:31`をactual evidenceに合わせ、少なくとも次を分離する。

1. 実装済み・local green
2. immutable clean commitで再実行が必要
3. remote Linux/macOS greenが必要
4. independent reviewが必要

文書更新後、README、compatibility matrix、Host SDK guide、completion work ledgerの4面を
同じcommitで照合するgateまたはreview checklistを通す。

## P2 findings

### P2-1: CMake package version compatibilityが0.x SemVer policyより広い

`CMakeLists.txt:1013-1016`は`NinlilConfigVersion.cmake`を
`COMPATIBILITY SameMajorVersion`で生成する。一方、
`docs/06-versioning-and-compatibility.md:35-40`は0.xでminor bump時のbreaking changeを
許している。

このまま将来0.2.xをinstallすると、0.1 APIを要求するconsumerにmajor 0だけを根拠として
compatibleと判定される可能性がある。current 0.1.0単独の配布を直ちに壊す問題ではないが、
次minor release前には修正が必要である。

最小受入条件:

- `SameMinorVersion`または0.xを特別扱いするcustom version policyへ変更する。
- 0.1 requestに0.1.xはaccept、0.2.xはreject、1.xはrejectするinstalled consumer
  version-selection testを追加する。

### P2-2: repository rootにownership不明のgenerated junkが残り、誤stageしやすい

監査時にuntracked `./-`（1,859 bytes）、`./-.su`（0 bytes）、
`tmp-a2/qa-regression-log-a2a2.txt`を確認した。前者2件は
`.gitignore:1-38`の既知build artifact policyに含まれず、`git add -A`で配布候補へ
混入し得る。`tmp-a2`はP1-3の非hermetic test outputである。

最小受入条件:

- producerと用途を特定し、不要なら削除する。
- 必要なgenerated outputはrepository rootではなくignored build/temp directoryへ出す。
- clean candidateで`git status --short`が空であり、source archive denylistにも
  混入しないことを確認する。

### P2-3: current 0.1.0文書にfuture `v1.1.0`の実値例が残る

canonical project versionは`0.1.0`だが、次に`v1.1.0`が実値例として残る。

- `.github/ISSUE_TEMPLATE/bug_report.yml:15`
- `.github/ISSUE_TEMPLATE/question.yml:17`
- `docs/releasing.md:168-176`

historical prereleaseも存在するため、利用者がcurrent SDK seriesまたは次tagを誤認しやすい。

最小受入条件:

- issue templateは`v0.1.0`または`<release-tag>`へ置換する。
- attestation commandはcurrent release variableを使うcopy-safeな例にする。
- release_version_identityのself-testとMarkdown link gateを再実行する。

## 確認済みのgreen evidence

次はcurrent worktreeに対して成功した。ただしP1-1によりimmutable release evidenceではない。

| Area | Result |
| --- | --- |
| Apache-2.0 | full `LICENSE` bytesとpinned hashがgate一致 |
| NOTICE / third-party | `third_party_notice_gate.py check/self-test`成功 |
| Dependency inventory | OpenSSL、SQLite、ESP-IDF/TinyUSB、vendored PyYAML 6.0.2を収録 |
| Vendored PyYAML | `dependency-inventory.json:28-40`、MIT notice、source hash、SBOM reconciliationあり。vendor source約225 KiBで過大ではない |
| SBOM | `spdx_release_sbom.py self-test`成功。release workflowはSyft raw SBOMをinventoryでenrich/check |
| Compatibility | `compatibility_matrix_gate.py check/self-test`成功 |
| Version identity | `release_version_identity.py self-test`成功、core version `0.1.0` |
| Workflow identity | `release_workflow_identity_gate.py check/self-test`成功 |
| Vocabulary / links | release vocabulary gate、Markdown link gateのcheck/self-test成功 |
| CMake install | tests-OFF Host Runtime、SQLite ON/OFF、Domain ON installed consumer成功 |
| Public headers | C11/C++17 self-contained public header test成功 |
| ABI | drift、negative、manifest repeatability/golden/coverage、contract header/output/enum成功 |
| Archive | worktree two-run deterministic、tar/zip payload equivalence、clean-room install consumer成功 |
| Archive size | worktree `tar.gz`約8.47 MiB、`zip`約9.49 MiB |

`THIRD-PARTY-NOTICES.md`と`dependency-inventory.json`のPyYAML追加は、release workflowの
semantic YAML gateをoffline/reproducibleにする目的と釣り合っている。今回のlarge-file
問題はvendored dependencyではなく、D3-S4 generated oracleとそのtest execution modelである。

## Release re-GO checklist

次をすべて同一full commit SHAで閉じた場合にだけ再監査する。

```sh
test -z "$(git status --porcelain=v1)"
git diff --check

python3 tools/compatibility_matrix_gate.py check
python3 tools/compatibility_matrix_gate.py self-test
python3 tools/third_party_notice_gate.py check
python3 tools/third_party_notice_gate.py self-test
python3 tools/release_version_identity.py self-test
python3 tools/release_workflow_identity_gate.py check
python3 tools/release_workflow_identity_gate.py self-test
python3 tools/spdx_release_sbom.py self-test
python3 tools/markdown_link_gate.py check
python3 tools/markdown_link_gate.py self-test
python3 tools/release_distribution_authority_gate.py check
python3 tools/release_distribution_authority_gate.py self-test

python3 tools/release_archive_payload_gate.py \
  build-from-git --two-run --source git --treeish HEAD \
  --prefix ninlil-runtime-candidate
```

その後:

1. fresh Linux Release + sanitizer + installed consumer
2. fresh macOS Release + sanitizer + installed consumer
3. pinned ESP-IDF v5.5.3 ESP32-S3 compile/link/map
4. D3-S4 oracleのresource budgetとsource-tree cleanliness
5. `workflow_dispatch(ref=<full SHA>)`
6. downloaded 5 dry-run filesの独立照合
7. tag pathの7 attested filesをdraft releaseで照合

P1を閉じるまでは、local worktreeのtest件数、概算完成率、archive生成成功を根拠に
`RELEASE_SUPPORTED`または公開準備完了と記載してはならない。
